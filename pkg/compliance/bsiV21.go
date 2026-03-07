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

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

var (
	// BSI v2.1 requires CycloneDX >= 1.6, SPDX >= 3.0.1 (SPDX v2 not allowed)
	validBsiV21CdxVersions = []string{"1.6"}
)

func bsiV21Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiV21Result()")

	dtb := db.NewDB()

	// SBOM-level checks
	dtb.AddRecord(bsiV21Vulnerabilities(doc))
	dtb.AddRecord(bsiSpec(doc))
	dtb.AddRecord(bsiV21SpecVersion(doc))
	dtb.AddRecord(bsiBuildPhase(doc))
	dtb.AddRecord(bsiv11SBOMCreator(doc))
	dtb.AddRecord(bsiv11SBOMTimestamp(doc))
	dtb.AddRecord(bsiV21SBOMURI(doc))

	// Component-level checks
	dtb.AddRecords(bsiV21Components(doc))

	if outFormat == pkgcommon.FormatJSON {
		bsiV21JSONReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		bsiV21BasicReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		bsiV21DetailedReport(dtb, fileName)
	}
}

// bsiV21SpecVersion checks that the SBOM format meets BSI v2.1 minimum version requirements.
// CycloneDX >= 1.6, SPDX v2 is NOT allowed (requires >= 3.0.1).
func bsiV21SpecVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result, score := "", 0.0

	if spec == string(sbom.SBOMSpecSPDX) {
		// SPDX v2 is NOT allowed by BSI v2.1. Only SPDX >= 3.0.1 is valid.
		// Since sbomqs doesn't support SPDX3 yet, all SPDX v2 SBOMs fail.
		result = version + " (SPDX v2 not allowed by BSI v2.1)"
		score = 0.0
	} else if spec == string(sbom.SBOMSpecCDX) {
		if bsiV21CdxVersionAtLeast(version) {
			result = version
			score = 10.0
		} else {
			result = version + " (requires >= 1.6)"
			score = 0.0
		}
	}

	return db.NewRecordStmt(SBOM_SPEC_VERSION, "doc", result, score, "")
}

// bsiV21CdxVersionAtLeast checks if a CDX version is >= 1.6.
func bsiV21CdxVersionAtLeast(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	var major, minor int
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return false
	}

	if major > 1 {
		return true
	}
	return major == 1 && minor >= 6
}

// bsiV21SBOMURI checks for the SBOM-URI field. In v2.1 this is a SHALL (required) field.
func bsiV21SBOMURI(doc sbom.Document) *db.Record {
	uri := strings.TrimSpace(doc.Spec().GetURI())

	if uri == "" {
		return db.NewRecordStmt(SBOM_URI, "doc", "", 0.0, "")
	}

	if !bsiIsValidURL(uri) && !strings.HasPrefix(uri, "urn:") {
		return db.NewRecordStmt(SBOM_URI, "doc", uri, 0.0, "")
	}

	result := strings.Join(breakLongString(uri, 80), "\n")
	return db.NewRecordStmt(SBOM_URI, "doc", result, 10.0, "")
}

// bsiV21Vulnerabilities checks that the SBOM does NOT contain vulnerability info.
// BSI v2.1 section 3.1: SBOM MUST NOT contain vulnerability information.
func bsiV21Vulnerabilities(doc sbom.Document) *db.Record {
	result, score := "no-vulnerability", 10.0

	vulns := doc.Vulnerabilities()
	allVulnIDs := make([]string, 0, len(vulns))

	for _, v := range vulns {
		if vulnID := v.GetID(); vulnID != "" {
			allVulnIDs = append(allVulnIDs, vulnID)
		}
	}

	if len(allVulnIDs) > 0 {
		result = strings.Join(allVulnIDs, ", ")
		score = 0.0
	}
	return db.NewRecordStmt(SBOM_VULNERABILITIES, "doc", result, score, "")
}

func bsiV21Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		// Required (SHALL) component fields
		records = append(records, bsiv11ComponentCreator(component))
		records = append(records, bsiv11ComponentName(component))
		records = append(records, bsiv11ComponentVersion(component))
		records = append(records, bsiV21ComponentFilename(component))
		records = append(records, bsiv11ComponentDependencies(doc, component))
		records = append(records, bsiV21ComponentDistributionLicense(component))
		records = append(records, bsiV21ComponentDeployableHash(component))
		records = append(records, bsiV21ComponentExecutable(component))
		records = append(records, bsiV21ComponentArchive(component))
		records = append(records, bsiV21ComponentStructured(component))
		records = append(records, bsiV21ComponentSourceCodeURL(component))
		records = append(records, bsiV21ComponentDownloadURL(component))
		records = append(records, bsiV21ComponentOtherIdentifiers(component))
		records = append(records, bsiV21ComponentOriginalLicenses(component))

		// Optional (MAY) component fields
		records = append(records, bsiV21ComponentEffectiveLicense(component))
		records = append(records, bsiV21ComponentSourceHash(component))
		records = append(records, bsiV21ComponentSecurityTxtURL(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

// bsiV21ComponentFilename checks for the bsi:component:filename property (SHALL).
func bsiV21ComponentFilename(component sbom.GetComponent) *db.Record {
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:filename"))

	if value != "" {
		return db.NewRecordStmt(COMP_FILENAME, common.UniqueElementID(component), value, 10.0, "")
	}

	return db.NewRecordStmt(COMP_FILENAME, common.UniqueElementID(component), "", 0.0, "")
}

// bsiV21ComponentExecutable checks for the bsi:component:executable property (SHALL).
func bsiV21ComponentExecutable(component sbom.GetComponent) *db.Record {
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:executable"))

	if value != "" {
		return db.NewRecordStmt(COMP_EXECUTABLE, common.UniqueElementID(component), value, 10.0, "")
	}

	return db.NewRecordStmt(COMP_EXECUTABLE, common.UniqueElementID(component), "", 0.0, "")
}

// bsiV21ComponentArchive checks for the bsi:component:archive property (SHALL).
func bsiV21ComponentArchive(component sbom.GetComponent) *db.Record {
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:archive"))

	if value != "" {
		return db.NewRecordStmt(COMP_ARCHIVE, common.UniqueElementID(component), value, 10.0, "")
	}

	return db.NewRecordStmt(COMP_ARCHIVE, common.UniqueElementID(component), "", 0.0, "")
}

// bsiV21ComponentStructured checks for the bsi:component:structured property (SHALL).
func bsiV21ComponentStructured(component sbom.GetComponent) *db.Record {
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:structured"))

	if value != "" {
		return db.NewRecordStmt(COMP_STRUCTURED, common.UniqueElementID(component), value, 10.0, "")
	}

	return db.NewRecordStmt(COMP_STRUCTURED, common.UniqueElementID(component), "", 0.0, "")
}

// bsiV21ComponentDistributionLicense checks for concluded licenses (SHALL).
// BSI v2.1: Distribution licences require acknowledgement="concluded".
func bsiV21ComponentDistributionLicense(component sbom.GetComponent) *db.Record {
	licenses := component.ConcludedLicenses()

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "not-compliant", 0.0, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

// bsiV21ComponentOriginalLicenses checks for declared licenses (SHALL).
// BSI v2.1: Original licences require acknowledgement="declared".
func bsiV21ComponentOriginalLicenses(component sbom.GetComponent) *db.Record {
	licenses := component.DeclaredLicenses()

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "not-compliant", 0.0, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

// bsiV21ComponentDeployableHash checks for hash via externalReferences with type="distribution" (SHALL).
func bsiV21ComponentDeployableHash(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		if er.GetRefType() == "distribution" {
			for _, h := range er.GetRefHashes() {
				content := strings.TrimSpace(h.GetContent())
				if content != "" {
					algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
					return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, id, algo+": "+content, 10.0, "")
				}
			}
		}
	}

	return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, id, "", 0.0, "")
}

// bsiV21ComponentSourceCodeURL checks for source code URI via externalReferences type="source-distribution" (SHALL).
func bsiV21ComponentSourceCodeURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		if er.GetRefType() == "source-distribution" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator != "" && bsiIsValidURL(locator) {
				return db.NewRecordStmt(COMP_SOURCE_CODE_URL, id, locator, 10.0, "")
			}
		}
	}

	// Fallback: check existing source code URL field (for vcs type)
	result := strings.TrimSpace(component.GetSourceCodeURL())
	if result != "" && bsiIsValidURL(result) {
		return db.NewRecordStmt(COMP_SOURCE_CODE_URL, id, result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_SOURCE_CODE_URL, id, "", 0.0, "")
}

// bsiV21ComponentDownloadURL checks for deployable URI via externalReferences type="distribution" (SHALL).
func bsiV21ComponentDownloadURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		if er.GetRefType() == "distribution" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator != "" && bsiIsValidURL(locator) {
				return db.NewRecordStmt(COMP_DOWNLOAD_URL, id, locator, 10.0, "")
			}
		}
	}

	// Fallback: check existing download location URL field
	result := strings.TrimSpace(component.GetDownloadLocationURL())
	if result != "" && bsiIsValidURL(result) {
		return db.NewRecordStmt(COMP_DOWNLOAD_URL, id, result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_DOWNLOAD_URL, id, "", 0.0, "")
}

// bsiV21ComponentOtherIdentifiers checks for CPE, SWID, or PURL (SHALL).
func bsiV21ComponentOtherIdentifiers(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check PURLs
	for _, p := range component.GetPurls() {
		v := strings.TrimSpace(string(p))
		if v != "" {
			return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, id, "purl: "+v, 10.0, "")
		}
	}

	// Check CPEs
	for _, cpe := range component.GetCpes() {
		v := strings.TrimSpace(string(cpe))
		if v != "" {
			return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, id, "cpe: "+v, 10.0, "")
		}
	}

	// Check SWIDs
	for _, s := range component.Swids() {
		if s.GetTagID() != "" {
			return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, id, "swid: "+s.GetTagID(), 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_OTHER_UNIQ_IDS, id, "", 0.0, "")
}

// bsiV21ComponentEffectiveLicense checks for the bsi:component:effectiveLicense property (MAY).
func bsiV21ComponentEffectiveLicense(component sbom.GetComponent) *db.Record {
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:effectiveLicense"))

	if value != "" {
		return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, common.UniqueElementID(component), value, 10.0)
	}

	return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, common.UniqueElementID(component), "", 0.0)
}

// bsiV21ComponentSourceHash checks for hash via externalReferences type="source-distribution" (MAY).
func bsiV21ComponentSourceHash(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		if er.GetRefType() == "source-distribution" {
			for _, h := range er.GetRefHashes() {
				content := strings.TrimSpace(h.GetContent())
				if content != "" {
					algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
					return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, algo+": "+content, 10.0)
				}
			}
		}
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, "", 0.0)
}

// bsiV21ComponentSecurityTxtURL checks for externalReferences type="rfc-9116" (MAY).
func bsiV21ComponentSecurityTxtURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		if er.GetRefType() == "rfc-9116" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator != "" {
				return db.NewRecordStmtOptional(COMP_SECURITY_TXT_URL, id, locator, 10.0)
			}
		}
	}

	return db.NewRecordStmtOptional(COMP_SECURITY_TXT_URL, id, "", 0.0)
}


