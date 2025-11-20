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

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validSpdxVersion     = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

//nolint:revive,stylecheck
const (
	SBOM_SPEC = iota
	SBOM_SPDXID
	SBOM_NAME
	SBOM_COMMENT
	SBOM_ORG
	SBOM_TOOL
	SBOM_NAMESPACE
	SBOM_LICENSE
	SBOM_SPEC_VERSION
	SBOM_BUILD
	SBOM_DEPTH
	SBOM_CREATOR
	SBOM_TIMESTAMP
	SBOM_COMPONENTS
	SBOM_PACKAGES
	SBOM_URI
	COMP_CREATOR
	PACK_SUPPLIER
	COMP_NAME
	COMP_VERSION
	PACK_HASH
	COMP_HASH
	COMP_SOURCE_CODE_URL
	PACK_FILE_ANALYZED
	PACK_SPDXID
	PACK_NAME
	PACK_VERSION
	PACK_DOWNLOAD_URL
	COMP_DOWNLOAD_URL
	COMP_OTHER_UNIQ_IDS
	COMP_SOURCE_HASH
	COMP_LICENSE
	PACK_LICENSE_CON
	PACK_LICENSE_DEC
	PACK_COPYRIGHT
	COMP_DEPTH
	SBOM_MACHINE_FORMAT
	SBOM_DEPENDENCY
	SBOM_HUMAN_FORMAT
	SBOM_BUILD_INFO
	SBOM_DELIVERY_TIME
	SBOM_DELIVERY_METHOD
	SBOM_SCOPE
	PACK_INFO
	SBOM_TYPE
	PACK_EXT_REF
	SBOM_VULNERABILITIES
	SBOM_BOM_LINKS
	COMP_ASSOCIATED_LICENSE
	COMP_CONCLUDED_LICENSE
	COMP_DECLARED_LICENSE
	SBOM_SIGNATURE
)

func bsiResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiResult()")

	dtb := db.NewDB()

	dtb.AddRecord(bsiSpec(doc))
	dtb.AddRecord(bsiSpecVersion(doc))
	dtb.AddRecord(bsiBuildPhase(doc))
	dtb.AddRecord(bsiSbomDepth(doc))
	dtb.AddRecord(bsiCreator(doc))
	dtb.AddRecord(bsiTimestamp(doc))
	dtb.AddRecord(bsiSbomURI(doc))
	dtb.AddRecords(bsiComponents(doc))

	if outFormat == "json" {
		bsiJSONReport(dtb, fileName)
	}

	if outFormat == "basic" {
		bsiBasicReport(dtb, fileName)
	}

	if outFormat == "detailed" {
		bsiDetailedReport(dtb, fileName, colorOutput)
	}
}

// bsiSpec returns the spec type of the SBOM document.
// spec type can be either SPDX or CycloneDX.
func bsiSpec(doc sbom.Document) *db.Record {
	v := doc.Spec().GetSpecType()
	vToLower := strings.Trim(strings.ToLower(v), " ")
	result := ""
	score := 0.0

	if vToLower == string(sbom.SBOMSpecSPDX) {
		result = v
		score = 10.0
	} else if vToLower == string(sbom.SBOMSpecCDX) {
		result = v
		score = 10.0
	}
	return db.NewRecordStmt(SBOM_SPEC, "doc", result, score, "")
}

func bsiSpecVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result := ""
	score := 0.0

	if spec == string(sbom.SBOMSpecSPDX) {
		count := lo.Count(validBsiSpdxVersions, version)
		validate := lo.Contains(validSpdxVersion, version)
		if validate {
			if count > 0 {
				result = version
				score = 10.0
			} else {
				result = version
				score = 0.0
			}
		}
	} else if spec == string(sbom.SBOMSpecCDX) {
		count := lo.Count(validBsiCdxVersions, version)
		if count > 0 {
			result = version
			score = 10.0
		}
	}

	return db.NewRecordStmt(SBOM_SPEC_VERSION, "doc", result, score, "")
}

func bsiBuildPhase(doc sbom.Document) *db.Record {
	lifecycles := doc.Lifecycles()
	result := ""
	score := 0.0

	found := lo.Count(lifecycles, "build")

	if found > 0 {
		result = "build"
		score = 10.0
	}

	return db.NewRecordStmt(SBOM_BUILD, "doc", result, score, "")
}

func bsiSbomDepth(doc sbom.Document) *db.Record {
	result, score := "", 0.0
	// for doc.Components()
	totalDependencies := doc.PrimaryComp().GetTotalNoOfDependencies()

	if totalDependencies > 0 {
		score = 10.0
	}
	result = fmt.Sprintf("doc has %d dependencies", totalDependencies)

	// if len(doc.Relations()) == 0 {
	// 	return db.NewRecordStmt(SBOM_DEPTH, "doc", "no-relationships", 0.0, "")
	// }

	// primary, _ := lo.Find(doc.Components(), func(c sbom.GetComponent) bool {
	// 	return c.IsPrimaryComponent()
	// })

	// if !primary.HasRelationShips() {
	// 	return db.NewRecordStmt(SBOM_DEPTH, "doc", "no-primary-relationships", 0.0, "")
	// }

	// if primary.RelationShipState() == "complete" {
	// 	return db.NewRecordStmt(SBOM_DEPTH, "doc", "complete", 10.0, "")
	// }

	// if primary.HasRelationShips() {
	// 	return db.NewRecordStmt(SBOM_DEPTH, "doc", "unattested-has-relationships", 5.0, "")
	// }

	return db.NewRecordStmt(SBOM_DEPTH, "doc", result, score, "")
}

func bsiCreator(doc sbom.Document) *db.Record {
	result := ""
	score := 0.0

	for _, author := range doc.Authors() {
		if author.GetEmail() != "" {
			result = author.GetEmail()
			score = 10.0
			break
		}
	}

	if result != "" {
		return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
	}

	supplier := doc.Supplier()

	if supplier != nil {
		if supplier.GetEmail() != "" {
			result = supplier.GetEmail()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
		}

		if supplier.GetURL() != "" {
			result = supplier.GetURL()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
		}

		if supplier.GetContacts() != nil {
			for _, contact := range supplier.GetContacts() {
				if contact.GetEmail() != "" {
					result = contact.GetEmail()
					score = 10.0
					break
				}
			}

			if result != "" {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
			}
		}
	}

	manufacturer := doc.Manufacturer()

	if manufacturer != nil {
		if manufacturer.GetEmail() != "" {
			result = manufacturer.GetEmail()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
		}

		if manufacturer.GetURL() != "" {
			result = manufacturer.GetURL()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
		}

		if manufacturer.GetContacts() != nil {
			for _, contact := range manufacturer.GetContacts() {
				if contact.GetEmail() != "" {
					result = contact.GetEmail()
					score = 10.0
					break
				}
			}

			if result != "" {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", result, score, "")
			}
		}
	}
	return db.NewRecordStmt(SBOM_CREATOR, "doc", "", 0.0, "")
}

func bsiTimestamp(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if result = doc.Spec().GetCreationTimestamp(); result != "" {
		if _, isTimeCorrect := common.CheckTimestamp(result); isTimeCorrect {
			score = 10.0
		}
	}
	return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", result, score, "")
}

func bsiSbomURI(doc sbom.Document) *db.Record {
	uri := doc.Spec().GetURI()

	if uri != "" {
		brokenResult := breakLongString(uri, 50)
		result := strings.Join(brokenResult, "\n")
		return db.NewRecordStmt(SBOM_URI, "doc", result, 10.0, "")
	}

	return db.NewRecordStmt(SBOM_URI, "doc", "", 0.0, "")
}

var (
	bsiCompIDWithName               = make(map[string]string)
	bsiComponentList                = make(map[string]bool)
	bsiPrimaryDependencies          = make(map[string]bool)
	bsiGetAllPrimaryDepenciesByName = []string{}
)

func bsiComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	bsiCompIDWithName = common.ComponentsNamesMapToIDs(doc)
	bsiComponentList = common.ComponentsLists(doc)
	bsiPrimaryDependencies = common.MapPrimaryDependencies(doc)
	dependencies := common.GetAllPrimaryComponentDependencies(doc)
	isBsiAllDepesPresentInCompList := common.CheckPrimaryDependenciesInComponentList(dependencies, bsiComponentList)

	if isBsiAllDepesPresentInCompList {
		bsiGetAllPrimaryDepenciesByName = common.GetDependenciesByName(dependencies, bsiCompIDWithName)
	}

	for _, component := range doc.Components() {
		records = append(records, bsiComponentCreator(component))
		records = append(records, bsiComponentName(component))
		records = append(records, bsiComponentVersion(component))
		records = append(records, bsiComponentLicense(component))
		records = append(records, bsiComponentDepth(doc, component))
		records = append(records, bsiComponentHash(component))
		records = append(records, bsiComponentSourceCodeURL(component))
		records = append(records, bsiComponentDownloadURL(component))
		records = append(records, bsiComponentSourceHash(component))
		records = append(records, bsiComponentOtherUniqIDs(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

func bsiComponentDepth(doc sbom.Document, component sbom.GetComponent) *db.Record {
	result, score := "", 0.0
	var dependencies []string
	var allDepByName []string

	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
		if component.GetPrimaryCompInfo().IsPresent() {
			result = strings.Join(bsiGetAllPrimaryDepenciesByName, ", ")
			score = 10.0
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, score, "")
		}

		dependencies = doc.GetRelationships(common.GetID(component.GetSpdxID()))
		if dependencies == nil {
			if bsiPrimaryDependencies[common.GetID(component.GetSpdxID())] {
				return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "included-in", 10.0, "")
			}
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-relationship", 0.0, "")
		}
		allDepByName = common.GetDependenciesByName(dependencies, bsiCompIDWithName)
		if bsiPrimaryDependencies[common.GetID(component.GetSpdxID())] {
			allDepByName = append([]string{"included-in"}, allDepByName...)
			result = strings.Join(allDepByName, ", ")
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
		}
		result = strings.Join(allDepByName, ", ")
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")

	} else if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
		if component.GetPrimaryCompInfo().IsPresent() {
			result = strings.Join(bsiGetAllPrimaryDepenciesByName, ", ")
			score = 10.0
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, score, "")
		}
		id := component.GetID()
		dependencies = doc.GetRelationships(id)
		if len(dependencies) == 0 {
			if bsiPrimaryDependencies[id] {
				return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "included-in", 10.0, "")
			}
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-relationship", 0.0, "")
		}
		allDepByName = common.GetDependenciesByName(dependencies, bsiCompIDWithName)
		if bsiPrimaryDependencies[id] {
			allDepByName = append([]string{"included-in"}, allDepByName...)
			result = strings.Join(allDepByName, ", ")
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
		}
		result = strings.Join(allDepByName, ", ")
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-relationships", 0.0, "")
}

func bsiComponentLicense(component sbom.GetComponent) *db.Record {
	licenses := component.GetLicenses()
	score := 0.0

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), "not-compliant", score, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

func bsiComponentSourceHash(component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0

	if component.SourceCodeHash() != "" {
		result = component.SourceCodeHash()
		score = 10.0
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_HASH, common.UniqueElementID(component), result, score)
}

func bsiComponentOtherUniqIDs(component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0

	purl := component.GetPurls()

	if len(purl) > 0 {
		result = string(purl[0])
		result := common.WrapLongTextIntoMulti(result, 100)
		score = 10.0

		return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score)
	}

	cpes := component.GetCpes()

	if len(cpes) > 0 {
		result = string(cpes[0])
		result := common.WrapLongTextIntoMulti(result, 100)
		score = 10.0

		return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score)
	}

	return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), "", 0.0)
}

func bsiComponentDownloadURL(component sbom.GetComponent) *db.Record {
	result := component.GetDownloadLocationURL()

	if result != "" {
		return db.NewRecordStmtOptional(COMP_DOWNLOAD_URL, common.UniqueElementID(component), result, 10.0)
	}
	return db.NewRecordStmtOptional(COMP_DOWNLOAD_URL, common.UniqueElementID(component), "", 0.0)
}

func bsiComponentSourceCodeURL(component sbom.GetComponent) *db.Record {
	result := component.GetSourceCodeURL()

	if result != "" {
		return db.NewRecordStmtOptional(COMP_SOURCE_CODE_URL, common.UniqueElementID(component), result, 10.0)
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_CODE_URL, common.UniqueElementID(component), "", 0.0)
}

func bsiComponentHash(component sbom.GetComponent) *db.Record {
	result := ""
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}
	score := 0.0

	checksums := component.GetChecksums()

	for _, checksum := range checksums {
		if lo.Count(algos, checksum.GetAlgo()) > 0 {
			result = checksum.GetContent()
			score = 10.0
			break
		}
	}

	return db.NewRecordStmt(COMP_HASH, common.UniqueElementID(component), result, score, "")
}

func bsiComponentVersion(component sbom.GetComponent) *db.Record {
	result := component.GetVersion()

	if result != "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "", 0.0, "")
}

func bsiComponentName(component sbom.GetComponent) *db.Record {
	result := component.GetName()

	if result != "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "", 0.0, "")
}

func bsiComponentCreator(component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0

	supplier := component.Suppliers()
	if supplier != nil {
		if supplier.GetEmail() != "" {
			result = supplier.GetEmail()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}

		if supplier.GetURL() != "" {
			result = supplier.GetURL()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}

		if supplier.GetContacts() != nil {
			for _, contact := range supplier.GetContacts() {
				if contact.GetEmail() != "" {
					result = contact.GetEmail()
					score = 10.0
					break
				}
			}

			if result != "" {
				return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
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
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}

		if manufacturer.GetURL() != "" {
			result = manufacturer.GetURL()
			score = 10.0
		}

		if result != "" {
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}

		if manufacturer.GetContacts() != nil {
			for _, contact := range manufacturer.GetContacts() {
				if contact.GetEmail() != "" {
					result = contact.GetEmail()
					score = 10.0
					break
				}
			}

			if result != "" {
				return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
			}
		}
	}

	return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), "", 0.0, "")
}
