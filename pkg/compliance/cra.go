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
	valid_cra_spdx_versions = []string{"SPDX-2.3"}
	valid_cra_cdx_versions  = []string{"1.4", "1.5", "1.6"}
)

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
	SBOM_HUMAN_FORMAT
	SBOM_BUILD_INFO
	SBOM_DELIVERY_TIME
	SBOM_DELIVERY_METHOD
	SBOM_SCOPE
	PACK_INFO
	PACK_EXT_REF
)

func craResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.craResult()")

	db := newDB()

	db.addRecord(craSpec(doc))
	db.addRecord(craSpecVersion(doc))
	db.addRecord(craBuildPhase(doc))
	db.addRecord(craSbomDepth(doc))
	db.addRecord(craCreator(doc))
	db.addRecord(craTimestamp(doc))
	db.addRecord(craSbomURI(doc))
	db.addRecords(craComponents(doc))

	if outFormat == "json" {
		craJsonReport(db, fileName)
	}

	if outFormat == "basic" {
		craBasicReport(db, fileName)
	}

	if outFormat == "detailed" {
		craDetailedReport(db, fileName)
	}
}

func craSpec(doc sbom.Document) *record {
	v := doc.Spec().SpecType()
	v_to_lower := strings.Trim(strings.ToLower(v), " ")
	result := ""
	score := 0.0

	if v_to_lower == "spdx" {
		result = v
		score = 10.0
	} else if v_to_lower == "cyclonedx" {
		result = v
		score = 10.0
	}
	return newRecordStmt(SBOM_SPEC, "doc", result, score)
}

func craSpecVersion(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	version := doc.Spec().Version()

	result := ""
	score := 0.0

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

	return newRecordStmt(SBOM_SPEC_VERSION, "doc", result, score)
}

func craBuildPhase(doc sbom.Document) *record {
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

func craSbomDepth(doc sbom.Document) *record {
	if !doc.PrimaryComponent() {
		return newRecordStmt(SBOM_DEPTH, "doc", "no-primary", 0.0)
	}

	if len(doc.Relations()) == 0 {
		return newRecordStmt(SBOM_DEPTH, "doc", "no-relationships", 0.0)
	}

	primary, _ := lo.Find(doc.Components(), func(c sbom.Component) bool {
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

func craCreator(doc sbom.Document) *record {
	result := ""
	score := 0.0

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
		if supplier.Email() != "" {
			result = supplier.Email()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "doc", result, score)
		}

		if supplier.Url() != "" {
			result = supplier.Url()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(SBOM_CREATOR, "doc", result, score)
		}

		if supplier.Contacts() != nil {
			for _, contact := range supplier.Contacts() {
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
	return newRecordStmt(SBOM_CREATOR, "doc", "", 0.0)
}

func craTimestamp(doc sbom.Document) *record {
	score := 0.0
	result := doc.Spec().CreationTimestamp()

	if result != "" {
		score = 10.0
	}

	return newRecordStmt(SBOM_TIMESTAMP, "doc", result, score)
}

func craSbomURI(doc sbom.Document) *record {
	uri := doc.Spec().URI()

	if uri != "" {
		return newRecordStmt(SBOM_URI, "doc", uri, 10.0)
	}

	return newRecordStmt(SBOM_URI, "doc", "", 0)
}

func craComponents(doc sbom.Document) []*record {
	records := []*record{}

	if len(doc.Components()) == 0 {
		records := append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, craComponentCreator(component))
		records = append(records, craComponentName(component))
		records = append(records, craComponentVersion(component))
		records = append(records, craComponentLicense(component))
		records = append(records, craComponentDepth(component))
		records = append(records, craComponentHash(component))
		records = append(records, craComponentSourceCodeUrl(component))
		records = append(records, craComponentDownloadUrl(component))
		records = append(records, craComponentSourceHash(component))
		records = append(records, craComponentOtherUniqIds(component))
	}

	records = append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0))

	return records
}

func craComponentDepth(component sbom.Component) *record {
	if !component.HasRelationShips() {
		return newRecordStmt(COMP_DEPTH, component.ID(), "no-relationships", 0.0)
	}

	if component.RelationShipState() == "complete" {
		return newRecordStmt(COMP_DEPTH, component.ID(), "complete", 10.0)
	}

	if component.HasRelationShips() {
		return newRecordStmt(COMP_DEPTH, component.ID(), "unattested-has-relationships", 5.0)
	}

	return newRecordStmt(COMP_DEPTH, component.ID(), "non-compliant", 0.0)
}

func craComponentLicense(component sbom.Component) *record {
	licenses := component.Licenses()
	score := 0.0

	if len(licenses) == 0 {
		// fmt.Printf("component %s : %s has no licenses\n", component.Name(), component.Version())
		return newRecordStmt(COMP_LICENSE, component.ID(), "not-compliant", score)
	}

	var spdx, aboutcode, custom int

	for _, license := range licenses {
		if license.Source() == "spdx" {
			spdx += 1
			continue
		}

		if license.Source() == "aboutcode" {
			aboutcode += 1
			continue
		}

		if license.Source() == "custom" {
			if strings.HasPrefix(license.ShortID(), "LicenseRef-") || strings.HasPrefix(license.Name(), "LicenseRef-") {
				custom += 1
				continue
			}
		}
	}

	total := spdx + aboutcode + custom

	// fmt.Printf("component %s : %s has (total)%d = (all)%d licenses\n", component.Name(), component.Version(), total, len(licenses))
	// fmt.Printf("%+v\n", licenses)

	if total != len(licenses) {
		score = 0.0
		return newRecordStmt(COMP_LICENSE, component.ID(), "not-compliant", score)
	}

	return newRecordStmt(COMP_LICENSE, component.ID(), "compliant", 10.0)
}

func craComponentSourceHash(component sbom.Component) *record {
	result := ""
	score := 0.0

	if component.SourceCodeHash() != "" {
		result = component.SourceCodeHash()
		score = 10.0
	}

	return newRecordStmtOptional(COMP_SOURCE_HASH, component.ID(), result, score)
}

func craComponentOtherUniqIds(component sbom.Component) *record {
	result := ""
	score := 0.0

	purl := component.Purls()

	if len(purl) > 0 {
		result = string(purl[0])
		score = 10.0

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.ID(), result, score)
	}

	cpes := component.Cpes()

	if len(cpes) > 0 {
		result = string(cpes[0])
		score = 10.0

		return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.ID(), result, score)
	}

	return newRecordStmtOptional(COMP_OTHER_UNIQ_IDS, component.ID(), "", 0.0)
}

func craComponentDownloadUrl(component sbom.Component) *record {
	result := component.DownloadLocationUrl()

	if result != "" {
		return newRecordStmtOptional(COMP_DOWNLOAD_URL, component.ID(), result, 10.0)
	}
	return newRecordStmtOptional(COMP_DOWNLOAD_URL, component.ID(), "", 0.0)
}

func craComponentSourceCodeUrl(component sbom.Component) *record {
	result := component.SourceCodeUrl()

	if result != "" {
		return newRecordStmtOptional(COMP_SOURCE_CODE_URL, component.ID(), result, 10.0)
	}

	return newRecordStmtOptional(COMP_SOURCE_CODE_URL, component.ID(), "", 0.0)
}

func craComponentHash(component sbom.Component) *record {
	result := ""
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}
	score := 0.0

	checksums := component.Checksums()

	for _, checksum := range checksums {
		if lo.Count(algos, checksum.Algo()) > 0 {
			result = checksum.Content()
			score = 10.0
			break
		}
	}

	return newRecordStmt(COMP_HASH, component.ID(), result, score)
}

func craComponentVersion(component sbom.Component) *record {
	result := component.Version()

	if result != "" {
		return newRecordStmt(COMP_VERSION, component.ID(), result, 10.0)
	}

	return newRecordStmt(COMP_VERSION, component.ID(), "", 0.0)
}

func craComponentName(component sbom.Component) *record {
	result := component.Name()

	if result != "" {
		return newRecordStmt(COMP_NAME, component.ID(), result, 10.0)
	}

	return newRecordStmt(COMP_NAME, component.ID(), "", 0.0)
}

func craComponentCreator(component sbom.Component) *record {
	result := ""
	score := 0.0

	supplier := component.Supplier()
	if supplier != nil {
		if supplier.Email() != "" {
			result = supplier.Email()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
		}

		if supplier.Url() != "" {
			result = supplier.Url()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
		}

		if supplier.Contacts() != nil {
			for _, contact := range supplier.Contacts() {
				if contact.Email() != "" {
					result = contact.Email()
					score = 10.0
					break
				}
			}

			if result != "" {
				return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
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
			return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
		}

		if manufacturer.Url() != "" {
			result = manufacturer.Url()
			score = 10.0
		}

		if result != "" {
			return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
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
				return newRecordStmt(COMP_CREATOR, component.ID(), result, score)
			}
		}
	}

	return newRecordStmt(COMP_CREATOR, component.ID(), "", 0.0)
}
