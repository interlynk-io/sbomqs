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
	spec := doc.Spec().GetSpecType()
	result, score := "", 0.0

	fileFormat := doc.Spec().FileFormat()
	if lo.Contains(validFormats, fileFormat) && lo.Contains(validSpec, spec) {
		result = spec + ", " + fileFormat
		score = 10.0
	} else {
		result = spec + ", " + fileFormat
	}
	return newRecordStmt(SBOM_MACHINE_FORMAT, "Automation Support", result, score)
}

func ntiaSBOMDependency(doc sbom.Document) *record {
	result, score := "", 0.0
	// for doc.Components()
	totalDependencies := doc.PrimaryComp().Dependencies()

	if totalDependencies > 0 {
		score = 10.0
	}
	result = fmt.Sprintf("doc has %d depedencies", totalDependencies)

	return newRecordStmt(SBOM_DEPENDENCY, "SBOM Data Fields", result, score)
}

// Required Sbom stuffs
func ntiaSbomCreator(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	result, score := "", 0.0

	if spec == "spdx" {
		name, email := "", ""
		if tools := doc.Tools(); tools != nil {
			for _, tool := range tools {
				if name = tool.GetName(); name != "" {
					result = name
					score = 10.0
					break
				}
			}
		}
		if authors := doc.Authors(); authors != nil {
			for _, author := range authors {
				if name = author.GetName(); name != "" {
					result = name
					score = 10.0
					break
				} else if email = author.GetEmail(); email != "" {
					result = name
					score = 10.0
					break
				}
			}
		}
	} else if spec == "cyclonedx" {
		for _, author := range doc.Authors() {
			if author.GetEmail() != "" {
				result = author.GetEmail()
				score = 10.0
				break
			}
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
		}

		tools := doc.Tools()

		for _, tool := range tools {
			if name := tool.GetName(); name != "" {
				result = name
				score = 10.0
				break
			}
		}

		supplier := doc.Supplier()

		if supplier != nil {
			if supplier.GetEmail() != "" {
				result = supplier.GetEmail()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

			if supplier.GetURL() != "" {
				result = supplier.GetURL()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

			for _, contact := range supplier.GetContacts() {
				if contact.Email() != "" {
					result = contact.Email()
					score = 10.0
					break
				}
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

		}

		manufacturer := doc.Manufacturer()

		if manufacturer != nil {
			if manufacturer.GetEmail() != "" {
				result = manufacturer.GetEmail()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

			if manufacturer.GetURL() != "" {
				result = manufacturer.GetURL()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

			for _, contact := range manufacturer.GetContacts() {
				if contact.Email() != "" {
					result = contact.Email()
					score = 10.0
					break
				}
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
			}

		}
	}
	return newRecordStmt(SBOM_CREATOR, "SBOM Data Fields", result, score)
}

func ntiaSbomCreatedTimestamp(doc sbom.Document) *record {
	score := 0.0
	result := doc.Spec().GetCreationTimestamp()

	if result != "" {
		_, err := time.Parse(time.RFC3339, result)
		if err != nil {
			score = 0.0
		} else {
			score = 10.0
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
		records = append(records, newRecordStmt(SBOM_COMPONENTS, "SBOM Data Fields", "absent", 0.0))
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
		return newRecordStmt(COMP_NAME, component.GetName(), result, 10.0)
	}
	return newRecordStmt(COMP_NAME, component.GetName(), "", 0.0)
}

func ntiaComponentCreator(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		if supplier := component.Suppliers().GetEmail(); supplier != "" {
			return newRecordStmt(PACK_SUPPLIER, component.GetName(), supplier, 10.0)
		}
	} else if spec == "cyclonedx" {
		result := ""
		score := 0.0

		supplier := component.Suppliers()
		if supplier != nil {
			if supplier.GetEmail() != "" {
				result = supplier.GetEmail()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
			}

			if supplier.GetURL() != "" {
				result = supplier.GetURL()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
			}

			if supplier.GetContacts() != nil {
				for _, contact := range supplier.GetContacts() {
					if contact.Email() != "" {
						result = contact.Email()
						score = 10.0
						break
					}
				}

				if result != "" {
					return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
				}
			}
		}

		manufacturer := component.Manufacturer()

		if manufacturer != nil {
			if manufacturer.GetEmail() != "" {
				result = manufacturer.GetEmail()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
			}

			if manufacturer.GetEmail() != "" {
				result = manufacturer.GetURL()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
			}

			if manufacturer.GetContacts() != nil {
				for _, contact := range manufacturer.GetContacts() {
					if contact.Email() != "" {
						result = contact.Email()
						score = 10.0
						break
					}
				}

				if result != "" {
					return newRecordStmt(COMP_CREATOR, component.GetName(), result, score)
				}
			}
		}
	}
	return newRecordStmt(COMP_CREATOR, component.GetName(), "", 0.0)
}

func ntiaComponentVersion(component sbom.GetComponent) *record {
	result := component.GetVersion()

	if result != "" {
		return newRecordStmt(COMP_VERSION, component.GetName(), result, 10.0)
	}

	return newRecordStmt(COMP_VERSION, component.GetName(), "", 0.0)
}

func ntiaComponentDependencies(doc sbom.Document, component sbom.GetComponent) *record {
	result, score := "", 0.0
	var results []string

	if relation := doc.Relations(); relation != nil {
		for _, rel := range relation {
			if strings.Contains(rel.GetFrom(), component.GetID()) {
				componentName := extractName(rel.GetTo())
				results = append(results, componentName)
				score = 10.0
			}
		}
	}
	if results != nil {
		for _, name := range results {
			result += name + ", "
		}
	} else {
		result += "No Dependencies"
	}

	return newRecordStmt(COMP_DEPTH, component.GetName(), result, score)
}

func ntiaComponentOtherUniqIDs(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		result, score, totalElements, containPurlElement := "", 0.0, 0, 0

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
			score = (float64(containPurlElement) / float64(totalElements)) * 10.0
			x := fmt.Sprintf(":(%d/%d)", containPurlElement, totalElements)
			result = result + x
		}
		return newRecordStmt(COMP_OTHER_UNIQ_IDS, component.GetName(), result, score)
	} else if spec == "cyclonedx" {
		result := ""
		score := 0.0

		purl := component.GetPurls()

		if len(purl) > 0 {
			result = string(purl[0])
			score = 10.0

			return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), result, score)
		}

		cpes := component.GetCpes()

		if len(cpes) > 0 {
			result = string(cpes[0])
			score = 10.0

			return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), result, score)
		}

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetName(), "", 0.0)
	}
	return newRecordStmt(COMP_OTHER_UNIQ_IDS, component.GetName(), "", 0.0)
}
