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
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func ntiaResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ntiaResult()")

	db := newDB()

	db.addRecord(ntiaSpec(doc))
	db.addRecord(ntiaSpecVersion(doc))
	db.addRecord(ntiaSbomCreator(doc))
	db.addRecord(ntiaSbomCreatedTimestamp(doc))
	db.addRecords(ntiaComponents(doc))
	// db.addRecord(ntiaBuildPhase(doc))
	// db.addRecord(ntiaComponentHash(doc))
	// db.addRecord(ntiaComponentlicense(doc))

	if outFormat == "json" {
		ntiaJsonReport(db, fileName)
	}

	if outFormat == "basic" {
		ntiaBasicReport(db, fileName)
	}

	if outFormat == "detailed" {
		ntiaDetailedReport(db, fileName)
	}
}

// format
func ntiaSpec(doc sbom.Document) *record {
	v := doc.Spec().GetSpecType()
	v_to_lower := strings.Trim(strings.ToLower(v), " ")
	result, score := "", 0.0

	if v_to_lower == "spdx" {
		result = v
		score = 10.0
	} else if v_to_lower == "cyclonedx" {
		result = v
		score = 10.0
	}
	return newRecordStmt(SBOM_SPEC, "SBOM format", result, score)
}

func ntiaSpecVersion(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result, score := "", 0.0

	if spec == "spdx" {
		count := lo.Count(valid_cra_spdx_versions, version)
		if count > 0 {
			result = version
			score = 10.0
		}
	} else if spec == "cyclonedx" {
		count := lo.Count(valid_cra_cdx_versions, version)
		if count > 0 {
			result = version
			score = 10.0
		}
	}
	return newRecordStmt(SBOM_SPEC_VERSION, "SBOM format", result, score)
}

// Required Sbom stuffs
func ntiaSbomCreator(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	result, score := "", 0.0

	if spec == "spdx" {
		name := ""
		if tools := doc.Tools(); tools != nil {
			for _, tool := range tools {
				if name = tool.GetName(); name != "" {
					result = name
					score = 10.0
					break
				}
			}
		}
		return newRecordStmt(SBOM_CREATOR, "doc", result, score)

	} else if spec == "cyclonedx" {

		for _, author := range doc.Authors() {
			if author.Email() != "" {
				result = author.Email()
				score = 10.0
				break
			}
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "doc", result, score)
		}

		supplier := doc.Supplier()

		if supplier != nil {
			if supplier.GetEmail() != "" {
				result = supplier.GetEmail()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "doc", result, score)
			}

			if supplier.GetUrl() != "" {
				result = supplier.GetUrl()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "doc", result, score)
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
					return newRecordStmt(SBOM_CREATOR, "doc", result, score)
				}
			}
		}

		manufacturer := doc.Manufacturer()

		if manufacturer != nil {
			if manufacturer.Email() != "" {
				result = manufacturer.Email()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "doc", result, score)
			}

			if manufacturer.Url() != "" {
				result = manufacturer.Url()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(SBOM_CREATOR, "doc", result, score)
			}

			if manufacturer.Contacts() != nil {
				for _, contact := range manufacturer.Contacts() {
					if contact.Email() != "" {
						result = contact.Email()
						score = 10.0
						break
					}
				}

				if result != "" {
					return newRecordStmt(SBOM_CREATOR, "doc", result, score)
				}
			}
		}
	}
	return newRecordStmt(SBOM_CREATOR, "doc", result, score)
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
	return newRecordStmt(SBOM_TIMESTAMP, "doc", result, score)
}

// Required component stuffs
func ntiaComponents(doc sbom.Document) []*record {
	records := []*record{}

	if len(doc.Components()) == 0 {
		records := append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, ntiaComponentCreator(doc, component))
		records = append(records, ntiaComponentName(component))
		records = append(records, ntiaComponentVersion(component))
		records = append(records, ntiaComponentOtherUniqIds(doc, component))
		records = append(records, ntiaComponentDependencies(doc, component))

	}
	records = append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0))
	return records
}

func ntiaComponentName(component sbom.GetComponent) *record {
	if result := component.GetName(); result != "" {
		return newRecordStmt(COMP_NAME, component.GetID(), result, 10.0)
	}
	return newRecordStmt(COMP_NAME, component.GetID(), "", 0.0)
}

func ntiaComponentCreator(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		if supplier := component.Suppliers().GetEmail(); supplier != "" {
			return newRecordStmt(PACK_SUPPLIER, component.GetID(), supplier, 10.0)
		}
		return newRecordStmt(PACK_SUPPLIER, component.GetID(), "", 0.0)
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
				return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
			}

			if supplier.GetUrl() != "" {
				result = supplier.GetUrl()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
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
					return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
				}
			}
		}

		manufacturer := component.Manufacturer()

		if manufacturer != nil {
			if manufacturer.Email() != "" {
				result = manufacturer.Email()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
			}

			if manufacturer.Url() != "" {
				result = manufacturer.Url()
				score = 10.0
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
			}

			if manufacturer.Contacts() != nil {
				for _, contact := range manufacturer.Contacts() {
					if contact.Email() != "" {
						result = contact.Email()
						score = 10.0
						break
					}
				}

				if result != "" {
					return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
				}
			}
		}

	}
	return newRecordStmt(COMP_CREATOR, component.GetID(), "", 0.0)
}

func ntiaComponentVersion(component sbom.GetComponent) *record {
	result := component.GetVersion()

	if result != "" {
		return newRecordStmt(COMP_VERSION, component.GetID(), result, 10.0)
	}

	return newRecordStmt(COMP_VERSION, component.GetID(), "", 0.0)
}

// func ntiaComponentDepth(doc sbom.Document) *record {}

func ntiaComponentDependencies(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		result, score := "", 0.0
		if relation := doc.Relations(); relation != nil {
			for _, rel := range relation {
				if rel.GetFrom() != "" && rel.GetTo() != "" {
					result = rel.GetFrom() + ", " + rel.GetTo()
					score = 10
					return newRecordStmt(COMP_DEPTH, component.GetID(), result, score)
				}
			}
		}

		return newRecordStmt(COMP_DEPTH, component.GetID(), result, score)

	} else if spec == "cyclonedx" {
		return craComponentDepth(component)
	}

	return newRecordStmt(COMP_DEPTH, component.GetID(), "", 0.0)
}

func ntiaComponentOtherUniqIds(doc sbom.Document, component sbom.GetComponent) *record {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		return octPackageExternalRefs(component)
	} else if spec == "cyclonedx" {
		return craComponentOtherUniqIds(component)
	}
	return newRecordStmt(COMP_OTHER_UNIQ_IDS, component.GetID(), "", 0.0)
}

// Recommended sbom stuffs
// lifecycle
// func ntiaBuildPhase(doc sbom.Document) *record {
// 	lifecycles := doc.Lifecycles()
// 	result, score := "", 0.0

// 	found := lo.Count(lifecycles, "build")

// 	if found > 0 {
// 		result = "build"
// 		score = 10.0
// 	}

// 	return newRecordStmt(SBOM_BUILD, "doc", result, score)
// }

// func ntiaSbomDepth(doc sbom.Document) *record {}

// Recommended component stuffs
// func ntiaComponentHash(doc sbom.Document) *record    {}
// func ntiaComponentlicense(doc sbom.Document) *record {}
