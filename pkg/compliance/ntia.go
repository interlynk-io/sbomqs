// Copyright 2025 Interlynk.io
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

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validSpec    = []string{pkgcommon.FormatCycloneDX, pkgcommon.FormatSPDX}
	validFormats = []string{pkgcommon.FormatJSON, pkgcommon.FormatXML, pkgcommon.FormatYAML, pkgcommon.FormatYML, pkgcommon.FormatTagValue}
)

// Scoring constants for NTIA compliance evaluation.
// These values represent the maximum and minimum scores for compliance checks.
//nolint
const (
	// SCORE_FULL represents the maximum score (10.0) when a compliance requirement is fully met.
	SCORE_FULL = 10.0
	// SCORE_ZERO represents the minimum score (0.0) when a compliance requirement is not met.
	SCORE_ZERO = 0.0
)

func ntiaResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ntiaResult()")

	db := db.NewDB()

	db.AddRecord(ntiaAutomationSpec(doc))
	db.AddRecord(ntiaSbomCreator(doc))
	db.AddRecord(ntiaSbomCreatedTimestamp(doc))
	db.AddRecord(ntiaSBOMDependency(doc))
	db.AddRecords(ntiaComponents(doc))

	if outFormat == pkgcommon.FormatJSON {
		ntiaJSONReport(db, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		ntiaBasicReport(db, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		ntiaDetailedReport(db, fileName, colorOutput)
	}
}

// format
func ntiaAutomationSpec(doc sbom.Document) *db.Record {
	result, score := "", SCORE_ZERO
	spec := doc.Spec().GetSpecType()
	fileFormat := doc.Spec().FileFormat()

	result = spec + ", " + fileFormat

	if lo.Contains(validFormats, fileFormat) && lo.Contains(validSpec, spec) {
		result = spec + ", " + fileFormat
		score = SCORE_FULL
	}
	return db.NewRecordStmt(SBOM_MACHINE_FORMAT, "Automation Support", result, score, "")
}

func ntiaSBOMDependency(doc sbom.Document) *db.Record {
	result, score := "", SCORE_ZERO
	totalRootDependencies := doc.PrimaryComp().GetTotalNoOfDependencies()

	if totalRootDependencies > 0 {
		score = SCORE_FULL
	}
	result = fmt.Sprintf("doc has %d dependencies", totalRootDependencies)

	return db.NewRecordStmt(SBOM_DEPENDENCY, "SBOM Data Fields", result, score, "")
}

func ntiaSbomCreator(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	result, score := "", SCORE_ZERO

	switch spec {
	case string(sbom.SBOMSpecSPDX):
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
	case string(sbom.SBOMSpecCDX):
		if authors := doc.Authors(); authors != nil {
			if authorResult, found := getAuthorInfo(authors); found {
				result = authorResult
				score = SCORE_FULL
				break
			}
		}
		if result != "" {
			return db.NewRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score, "")
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

	return db.NewRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score, "")
}

func getManufacturerInfo(manufacturer sbom.GetManufacturer) (string, bool) {
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
		if email := contact.GetEmail(); email != "" {
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
		if email := contact.GetEmail(); email != "" {
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

func ntiaSbomCreatedTimestamp(doc sbom.Document) *db.Record {
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
	return db.NewRecordStmt(SBOM_TIMESTAMP, "SBOM Data Fields", result, score, "")
}

var (
	compIDWithName               = make(map[string]string)
	componentList                = make(map[string]bool)
	primaryDependencies          = make(map[string]bool)
	// GetAllPrimaryDepenciesByName holds the names of all primary component dependencies
	// found in the SBOM document, used for NTIA compliance reporting.
	GetAllPrimaryDepenciesByName = []string{}
)

// Required component stuffs
func ntiaComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "SBOM Data Fields", "absent", SCORE_ZERO, ""))
		return records
	}

	compIDWithName = common.ComponentsNamesMapToIDs(doc)
	componentList = common.ComponentsLists(doc)
	primaryDependencies = common.MapPrimaryDependencies(doc)
	dependencies := common.GetAllPrimaryComponentDependencies(doc)
	areAllDepesPresentInCompList := common.CheckPrimaryDependenciesInComponentList(dependencies, componentList)

	if areAllDepesPresentInCompList {
		GetAllPrimaryDepenciesByName = common.GetDependenciesByName(dependencies, compIDWithName)
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

func ntiaComponentName(component sbom.GetComponent) *db.Record {
	if result := component.GetName(); result != "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "", SCORE_ZERO, "")
}

func ntiaComponentCreator(doc sbom.Document, component sbom.GetComponent) *db.Record {
	spec := doc.Spec().GetSpecType()
	result, score := "", SCORE_ZERO

	switch spec {
	case pkgcommon.FormatSPDX:
		if supplier := component.Suppliers(); supplier != nil {
			if supplierResult, found := getSupplierInfo(supplier); found {
				result = supplierResult
				score = SCORE_FULL
				break
			}
		}
	case pkgcommon.FormatCycloneDX:
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
	return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
}

func ntiaComponentVersion(component sbom.GetComponent) *db.Record {
	result := component.GetVersion()

	if result != "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, SCORE_FULL, "")
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "", SCORE_ZERO, "")
}

func ntiaComponentDependencies(doc sbom.Document, component sbom.GetComponent) *db.Record {
	result, score := "", SCORE_ZERO
	var dependencies []string
	var allDepByName []string

	if doc.Spec().GetSpecType() == pkgcommon.FormatSPDX {
		if component.GetPrimaryCompInfo().IsPresent() {
			result = strings.Join(GetAllPrimaryDepenciesByName, ", ")
			score = 10.0
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, score, "")
		}

		dependencies = doc.GetRelationships(common.GetID(component.GetSpdxID()))
		if dependencies == nil {

			if primaryDependencies[common.GetID(component.GetSpdxID())] {
				return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "included-in", 10.0, "")
			}
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-relationship", 0.0, "")

		}
		allDepByName = common.GetDependenciesByName(dependencies, compIDWithName)

		if primaryDependencies[common.GetID(component.GetSpdxID())] {
			allDepByName = append([]string{"included-in"}, allDepByName...)
			result = strings.Join(allDepByName, ", ")
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
		}

		result = strings.Join(allDepByName, ", ")
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")

	} else if doc.Spec().GetSpecType() == pkgcommon.FormatCycloneDX {
		if component.GetPrimaryCompInfo().IsPresent() {
			result = strings.Join(GetAllPrimaryDepenciesByName, ", ")
			score = 10.0
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, score, "")
		}
		id := component.GetID()
		dependencies = doc.GetRelationships(id)
		if len(dependencies) == 0 {
			if primaryDependencies[id] {
				return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "included-in", 10.0, "")
			}
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-relationship", 0.0, "")
		}
		allDepByName = common.GetDependenciesByName(dependencies, compIDWithName)
		if primaryDependencies[id] {
			allDepByName = append([]string{"included-in"}, allDepByName...)
			result = strings.Join(allDepByName, ", ")
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
		}
		result = strings.Join(allDepByName, ", ")
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")

	}
	return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, score, "")
}

func ntiaComponentOtherUniqIDs(doc sbom.Document, component sbom.GetComponent) *db.Record {
	spec := doc.Spec().GetSpecType()

	if spec == pkgcommon.FormatSPDX {
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
			result += x
		}
		return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score, "")
	} else if spec == pkgcommon.FormatCycloneDX {
		result := ""

		purl := component.GetPurls()

		if len(purl) > 0 {
			result = string(purl[0])
			result = common.WrapLongTextIntoMulti(result, 100)
			return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, SCORE_FULL)
		}

		cpes := component.GetCpes()

		if len(cpes) > 0 {
			result = string(cpes[0])
			result = common.WrapLongTextIntoMulti(result, 100)
			return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, SCORE_FULL)
		}

		return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), "", SCORE_ZERO)
	}
	return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), "", SCORE_ZERO, "")
}
