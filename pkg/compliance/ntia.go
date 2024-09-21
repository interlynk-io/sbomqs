// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validSpec    = []string{"cyclonedx", "spdx"}
	validFormats = []string{"json", "xml", "yaml", "yml", "tag-value"}
)

// nolint
const (
	SCORE_FULL = 10.0
	SCORE_ZERO = 0.0
)

func ntiaResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ntiaResult()")

	db := newDB()

	db.addRecord(ntiaAutomationSpec(doc))
	db.addRecord(ntiaSbomCreator(doc))
	db.addRecord(ntiaSbomCreatedTimestamp(doc))
	db.addRecord(ntiaSBOMDependency(doc))
	db.addRecords(ntiaComponents(doc))

	if outFormat == "json" {
		ntiaJSONReport(db, fileName)
	}

	if outFormat == "basic" {
		ntiaBasicReport(db, fileName)
	}

	if outFormat == "detailed" {
		ntiaDetailedReport(db, fileName)
	}
}

// format
func ntiaAutomationSpec(doc sbom.Document) *record {
	result, score := "", SCORE_ZERO
	spec := doc.Spec().GetSpecType()
	fileFormat := doc.Spec().FileFormat()

	result = spec + ", " + fileFormat

	if lo.Contains(validFormats, fileFormat) && lo.Contains(validSpec, spec) {
		result = spec + ", " + fileFormat
		score = SCORE_FULL
	}
	return newRecordStmt(SBOM_MACHINE_FORMAT, "Automation Support", result, score)
}

func ntiaSBOMDependency(doc sbom.Document) *record {
	result, score := "", SCORE_ZERO
	totalRootDependencies := doc.PrimaryComp().GetTotalNoOfDependencies()

	if totalRootDependencies > 0 {
		score = SCORE_FULL
	}
	result = fmt.Sprintf("doc has %d dependencies", totalRootDependencies)

	return newRecordStmt(SBOM_DEPENDENCY, "SBOM Data Fields", result, score)
}

func ntiaSbomCreator(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	result, score := "", SCORE_ZERO

	switch spec {
	case "spdx":
		if tools := doc.Tools(); tools != nil {
			if toolResult, found := getToolInfo(tools); found {
				result = toolResult
				score = SCORE_FULL
				break
			}
		}
		if authors := doc.Authors(); authors != nil {
			if authorResult, found := getAuthorInfo(authors); found {
				result = authorResult
				score = SCORE_FULL
				break
			}
		}
	case "cyclonedx":
		if authors := doc.Authors(); authors != nil {
			if authorResult, found := getAuthorInfo(authors); found {
				result = authorResult
				score = SCORE_FULL
				break
			}
		}
		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
		}
		if tools := doc.Tools(); tools != nil {
			if toolResult, found := getToolInfo(tools); found {
				result = toolResult
				score = SCORE_FULL
				break
			}
		}
		if supplier := doc.Supplier(); supplier != nil {
			if supplierResult, found := getSupplierInfo(supplier); found {
				result = supplierResult
				score = SCORE_FULL
				break
			}
		}
		if manufacturer := doc.Manufacturer(); manufacturer != nil {
			if manufacturerResult, found := getManufacturerInfo(manufacturer); found {
				result = manufacturerResult
				score = SCORE_FULL
				break
			}
		}
	}

	return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
}

func getManufacturerInfo(manufacturer sbom.Manufacturer) (string, bool) {
	if manufacturer == nil {
		return "", false
	}
	if email := manufacturer.GetEmail(); email != "" {
		return email, true
	}
	if url := manufacturer.GetURL(); url != "" {
		return url, true
	}
	for _, contact := range manufacturer.GetContacts() {
		if email := contact.Email(); email != "" {
			return email, true
		}
	}
	return "", false
}

func getSupplierInfo(supplier sbom.GetSupplier) (string, bool) {
	if supplier == nil {
		return "", false
	}
	if email := supplier.GetEmail(); email != "" {
		return email, true
	}
	if url := supplier.GetURL(); url != "" {
		return url, true
	}
	for _, contact := range supplier.GetContacts() {
		if email := contact.Email(); email != "" {
			return email, true
		}
	}
	return "", false
}

func getAuthorInfo(authors []sbom.GetAuthor) (string, bool) {
	for _, author := range authors {
		if email := author.GetEmail(); email != "" {
			return email, true
		}
		if name := author.GetName(); name != "" {
			return name, true
		}
	}
	return "", false
}

func getToolInfo(tools []sbom.GetTool) (string, bool) {
	for _, tool := range tools {
		if name := tool.GetName(); name != "" {
			return name, true
		}
	}
	return "", false
}

func ntiaSbomCreatedTimestamp(doc sbom.Document) *record {
	score := SCORE_ZERO
	result := doc.Spec().GetCreationTimestamp()

	if result != "" {
		_, err := time.Parse(time.RFC3339, result)
		if err != nil {
			score = SCORE_ZERO
		} else {
			score = SCORE_FULL
		}
	}
	return newRecordStmt(SBOM_TIMESTAMP, "SBOM Data Fields", result, score)
}

var CompIDWithName = make(map[string]string)

func extractName(comp string) string {
	for x, y := range CompIDWithName {
		if strings.Contains(comp, x) {
			return y
		}
	}
	return ""
}

// Required component stuffs
func ntiaComponents(doc sbom.Document) []*record {
	records := []*record{}

	if len(doc.Components()) == 0 {
		records = append(records, newRecordStmt(SBOM_COMPONENTS, "SBOM Data Fields", "absent", SCORE_ZERO))
		return records
	}

	// map package ID to Package Name
	for _, component := range doc.Components() {
		CompIDWithName[component.GetID()] = component.GetName()
	}

	for _, component := range doc.Components() {
		records = append(records, ntiaComponentName(component))
		records = append(records, ntiaComponentCreator(doc, component))
		records = append(records, ntiaComponentVersion(component))
		records = append(records, ntiaComponentOtherUniqIDs(doc, component))
		records = append(records, ntiaComponentDependencies(doc, component))
	}
	return records
}

func ntiaComponentName(component sbom.GetComponent) *record {
	if result := component.GetName(); result != "" {
		return newRecordStmt(COMP_NAME, component.GetName(), result, SCORE_FULL)
	}
	return newRecordStmt(COMP_NAME, component.GetName(), "", SCORE_ZERO)
}

func ntiaComponentCreator(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()
	result, score := "", SCORE_ZERO

	switch spec {
	case "spdx":
		if supplier := component.Suppliers(); supplier != nil {
			if supplierResult, found := getSupplierInfo(supplier); found {
				result = supplierResult
				score = SCORE_FULL
				break
			}
		}
	case "cyclonedx":
		if supplier := component.Suppliers(); supplier != nil {
			if supplierResult, found := getSupplierInfo(supplier); found {
				result = supplierResult
				score = SCORE_FULL
				break
			}
		}

		if manufacturer := component.Manufacturer(); manufacturer != nil {
			if manufacturerResult, found := getManufacturerInfo(manufacturer); found {
				result = manufacturerResult
				score = SCORE_FULL
				break
			}
		}
	}
	return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
}

func ntiaComponentVersion(component sbom.GetComponent) *record {
	result := component.GetVersion()

	if result != "" {
		return newRecordStmt(COMP_VERSION, component.GetName(), result, SCORE_FULL)
	}

	return newRecordStmt(COMP_VERSION, component.GetName(), "", SCORE_ZERO)
}

func ntiaComponentDependencies(doc sbom.Document, component sbom.GetComponent) *record {
	result, score := "", SCORE_ZERO
	var results []string

	dependencies := doc.GetRelationships(component.GetID())
	if dependencies == nil {
		return newRecordStmt(COMP_DEPTH, component.GetName(), "no-relationships", SCORE_ZERO)
	}
	for _, d := range dependencies {
		componentName := extractName(d)
		results = append(results, componentName)
		score = SCORE_FULL
	}

	if results != nil {
		result = strings.Join(results, ", ")
	} else {
		result += "no-relationships"
	}

	return newRecordStmt(COMP_DEPTH, component.GetName(), result, score)
}

func ntiaComponentOtherUniqIDs(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		result, score, totalElements, containPurlElement := "", SCORE_ZERO, 0, 0

		if extRefs := component.ExternalReferences(); extRefs != nil {
			for _, extRef := range extRefs {
				totalElements++
				result = extRef.GetRefType()
				if result == "purl" {
					containPurlElement++
				}
			}
		}
		if containPurlElement != 0 {
			score = (float64(containPurlElement) / float64(totalElements)) * SCORE_FULL
			x := fmt.Sprintf(":(%d/%d)", containPurlElement, totalElements)
			result = result + x
		}
		return newRecordStmt(COMP_OTHER_UNIQ_IDS, component.GetName(), result, score)
	} else if spec == "cyclonedx" {
		result := ""

		purl := component.GetPurls()

		if len(purl) > 0 {
			result = string(purl[0])

			return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), result, SCORE_FULL)
		}

		cpes := component.GetCpes()

		if len(cpes) > 0 {
			result = string(cpes[0])

			return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), result, SCORE_FULL)
		}

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), "", SCORE_ZERO)
	}
	return newRecordStmt(COMP_OTHER_UNIQ_IDS, component.GetName(), "", SCORE_ZERO)
}
