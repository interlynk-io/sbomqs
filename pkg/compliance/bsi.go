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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
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
	PACK_EXT_REF
)

func bsiResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiResult()")

	db := newDB()

	db.addRecord(bsiSpec(doc))
	db.addRecord(bsiSpecVersion(doc))
	db.addRecord(bsiBuildPhase(doc))
	db.addRecord(bsiSbomDepth(doc))
	db.addRecord(bsiCreator(doc))
	db.addRecord(bsiTimestamp(doc))
	db.addRecord(bsiSbomURI(doc))
	db.addRecords(bsiComponents(doc))

	if outFormat == "json" {
		bsiJSONReport(db, fileName)
	}

	if outFormat == "basic" {
		bsiBasicReport(db, fileName)
	}

	if outFormat == "detailed" {
		bsiDetailedReport(db, fileName)
	}
}

func bsiSpec(doc sbom.Document) *record {
	v := doc.Spec().GetSpecType()
	vToLower := strings.Trim(strings.ToLower(v), " ")
	result := ""
	score := 0.0

	if vToLower == "spdx" {
		result = v
		score = 10.0
	} else if vToLower == "cyclonedx" {
		result = v
		score = 10.0
	}
	return newRecordStmt(SBOM_SPEC, "doc", result, score)
}

func bsiSpecVersion(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result := ""
	score := 0.0

	if spec == "spdx" {
		count := lo.Count(validBsiSpdxVersions, version)
		if count > 0 {
			result = version
			score = 10.0
		}
	} else if spec == "cyclonedx" {
		count := lo.Count(validBsiCdxVersions, version)
		if count > 0 {
			result = version
			score = 10.0
		}
	}

	return newRecordStmt(SBOM_SPEC_VERSION, "doc", result, score)
}

func bsiBuildPhase(doc sbom.Document) *record {
	lifecycles := doc.Lifecycles()
	result := ""
	score := 0.0

	found := lo.Count(lifecycles, "build")

	if found > 0 {
		result = "build"
		score = 10.0
	}

	return newRecordStmt(SBOM_BUILD, "doc", result, score)
}

func bsiSbomDepth(doc sbom.Document) *record {
	if !doc.PrimaryComp().Present() {
		return newRecordStmt(SBOM_DEPTH, "doc", "no-primary", 0.0)
	}

	if len(doc.Relations()) == 0 {
		return newRecordStmt(SBOM_DEPTH, "doc", "no-relationships", 0.0)
	}

	primary, _ := lo.Find(doc.Components(), func(c sbom.GetComponent) bool {
		return c.IsPrimaryComponent()
	})

	if !primary.HasRelationShips() {
		return newRecordStmt(SBOM_DEPTH, "doc", "no-primary-relationships", 0.0)
	}

	if primary.RelationShipState() == "complete" {
		return newRecordStmt(SBOM_DEPTH, "doc", "complete", 10.0)
	}

	if primary.HasRelationShips() {
		return newRecordStmt(SBOM_DEPTH, "doc", "unattested-has-relationships", 5.0)
	}

	return newRecordStmt(SBOM_DEPTH, "doc", "non-compliant", 0.0)
}

func bsiCreator(doc sbom.Document) *record {
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

		if supplier.GetURL() != "" {
			result = supplier.GetURL()
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
		if manufacturer.GetEmail() != "" {
			result = manufacturer.GetEmail()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "doc", result, score)
		}

		if manufacturer.GetURL() != "" {
			result = manufacturer.GetURL()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "doc", result, score)
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
				return newRecordStmt(SBOM_CREATOR, "doc", result, score)
			}
		}
	}
	return newRecordStmt(SBOM_CREATOR, "doc", "", 0.0)
}

func bsiTimestamp(doc sbom.Document) *record {
	score := 0.0
	result := doc.Spec().GetCreationTimestamp()

	if result != "" {
		score = 10.0
	}

	return newRecordStmt(SBOM_TIMESTAMP, "doc", result, score)
}

func bsiSbomURI(doc sbom.Document) *record {
	uri := doc.Spec().URI()

	if uri != "" {
		return newRecordStmt(SBOM_URI, "doc", uri, 10.0)
	}

	return newRecordStmt(SBOM_URI, "doc", "", 0)
}

func bsiComponents(doc sbom.Document) []*record {
	records := []*record{}

	if len(doc.Components()) == 0 {
		records := append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, bsiComponentCreator(component))
		records = append(records, bsiComponentName(component))
		records = append(records, bsiComponentVersion(component))
		records = append(records, bsiComponentLicense(component))
		records = append(records, bsiComponentDepth(component))
		records = append(records, bsiComponentHash(component))
		records = append(records, bsiComponentSourceCodeURL(component))
		records = append(records, bsiComponentDownloadURL(component))
		records = append(records, bsiComponentSourceHash(component))
		records = append(records, bsiComponentOtherUniqIDs(component))
	}

	records = append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0))

	return records
}

func bsiComponentDepth(component sbom.GetComponent) *record {
	if !component.HasRelationShips() {
		return newRecordStmt(COMP_DEPTH, component.GetID(), "no-relationships", 0.0)
	}

	if component.RelationShipState() == "complete" {
		return newRecordStmt(COMP_DEPTH, component.GetID(), "complete", 10.0)
	}

	if component.HasRelationShips() {
		return newRecordStmt(COMP_DEPTH, component.GetID(), "unattested-has-relationships", 5.0)
	}

	return newRecordStmt(COMP_DEPTH, component.GetID(), "non-compliant", 0.0)
}

func bsiComponentLicense(component sbom.GetComponent) *record {
	licenses := component.Licenses()
	score := 0.0

	if len(licenses) == 0 {
		// fmt.Printf("component %s : %s has no licenses\n", component.Name(), component.Version())
		return newRecordStmt(COMP_LICENSE, component.GetID(), "not-compliant", score)
	}

	var spdx, aboutcode, custom int

	for _, license := range licenses {
		if license.Source() == "spdx" {
			spdx++
			continue
		}

		if license.Source() == "aboutcode" {
			aboutcode++
			continue
		}

		if license.Source() == "custom" {
			if strings.HasPrefix(license.ShortID(), "LicenseRef-") || strings.HasPrefix(license.Name(), "LicenseRef-") {
				custom++
				continue
			}
		}
	}

	total := spdx + aboutcode + custom

	// fmt.Printf("component %s : %s has (total)%d = (all)%d licenses\n", component.Name(), component.Version(), total, len(licenses))
	// fmt.Printf("%+v\n", licenses)

	if total != len(licenses) {
		score = 0.0
		return newRecordStmt(COMP_LICENSE, component.GetID(), "not-compliant", score)
	}

	return newRecordStmt(COMP_LICENSE, component.GetID(), "compliant", 10.0)
}

func bsiComponentSourceHash(component sbom.GetComponent) *record {
	result := ""
	score := 0.0

	if component.SourceCodeHash() != "" {
		result = component.SourceCodeHash()
		score = 10.0
	}

	return newRecordStmtOptional(COMP_SOURCE_HASH, component.GetID(), result, score)
}

func bsiComponentOtherUniqIDs(component sbom.GetComponent) *record {
	result := ""
	score := 0.0

	purl := component.GetPurls()

	if len(purl) > 0 {
		result = string(purl[0])
		score = 10.0

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetID(), result, score)
	}

	cpes := component.GetCpes()

	if len(cpes) > 0 {
		result = string(cpes[0])
		score = 10.0

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetID(), result, score)
	}

	return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.GetID(), "", 0.0)
}

func bsiComponentDownloadURL(component sbom.GetComponent) *record {
	result := component.GetDownloadLocationURL()

	if result != "" {
		return newRecordStmtOptional(COMP_DOWNLOAD_URL, component.GetID(), result, 10.0)
	}
	return newRecordStmtOptional(COMP_DOWNLOAD_URL, component.GetID(), "", 0.0)
}

func bsiComponentSourceCodeURL(component sbom.GetComponent) *record {
	result := component.SourceCodeURL()

	if result != "" {
		return newRecordStmtOptional(COMP_SOURCE_CODE_URL, component.GetID(), result, 10.0)
	}

	return newRecordStmtOptional(COMP_SOURCE_CODE_URL, component.GetID(), "", 0.0)
}

func bsiComponentHash(component sbom.GetComponent) *record {
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

	return newRecordStmt(COMP_HASH, component.GetID(), result, score)
}

func bsiComponentVersion(component sbom.GetComponent) *record {
	result := component.GetVersion()

	if result != "" {
		return newRecordStmt(COMP_VERSION, component.GetID(), result, 10.0)
	}

	return newRecordStmt(COMP_VERSION, component.GetID(), "", 0.0)
}

func bsiComponentName(component sbom.GetComponent) *record {
	result := component.GetName()

	if result != "" {
		return newRecordStmt(COMP_NAME, component.GetID(), result, 10.0)
	}

	return newRecordStmt(COMP_NAME, component.GetID(), "", 0.0)
}

func bsiComponentCreator(component sbom.GetComponent) *record {
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

		if supplier.GetURL() != "" {
			result = supplier.GetURL()
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
		if manufacturer.GetEmail() != "" {
			result = manufacturer.GetEmail()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
		}

		if manufacturer.GetURL() != "" {
			result = manufacturer.GetURL()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
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
				return newRecordStmt(COMP_CREATOR, component.GetID(), result, score)
			}
		}
	}

	return newRecordStmt(COMP_CREATOR, component.GetID(), "", 0.0)
}
