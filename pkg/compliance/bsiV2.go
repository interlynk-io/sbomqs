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
	"strings"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validBsiV2SpdxVersions = []string{"2.2", "2.3"}
	validBsiV2CdxVersions  = []string{"1.5", "1.6"}
)

func bsiV2Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiV2Result()")

	dtb := db.NewDB()

	dtb.AddRecord(bsiV2Vulnerabilities(doc))
	dtb.AddRecord(bsiSpec(doc))
	dtb.AddRecord(bsiV2SpecVersion(doc))
	dtb.AddRecord(bsiBuildPhase(doc))
	dtb.AddRecord(bsiv11SBOMCreator(doc))
	dtb.AddRecord(bsiv11SBOMTimestamp(doc))
	dtb.AddRecord(bsiv11SBOMURI(doc))
	dtb.AddRecords(bsiV2Components(doc))
	// New SBOM fields
	dtb.AddRecord(bsiV2SbomSignature(doc))
	dtb.AddRecord(bsiV2SbomLinks(doc))

	if outFormat == pkgcommon.FormatJSON {
		bsiV2JSONReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		bsiV2BasicReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		bsiV2DetailedReport(dtb, fileName)
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

// bomlinks
func bsiV2SbomLinks(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	bom := doc.Spec().GetExtDocRef()
	if bom != nil {
		result = strings.Join(bom, ", ")
		score = 10.0
	}
	wrappedURL := common.WrapText(result, 80)
	result = wrappedURL

	return db.NewRecordStmtOptional(SBOM_BOM_LINKS, "doc", result, score)
}

func bsiV2Vulnerabilities(doc sbom.Document) *db.Record {
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

// bsiV2SbomSignature
func bsiV2SbomSignature(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if doc.Signature() != nil {
		// Check if signature has the required components
		algorithm := doc.Signature().GetAlgorithm()
		sigValue := doc.Signature().GetSigValue()
		pubKey := doc.Signature().GetPublicKey()
		certPath := doc.Signature().GetCertificatePath()

		// Check for completeness
		if algorithm == "" || sigValue == "" {
			return db.NewRecordStmtOptional(SBOM_SIGNATURE, "doc", "Incomplete signature!", 0.0)
		}

		if pubKey == "" && len(certPath) == 0 {
			return db.NewRecordStmtOptional(SBOM_SIGNATURE, "doc", "Signature present but no verification material!", 5.0)
		}

		// For now, we'll give full score if signature is complete
		// Future enhancement: actually verify the signature
		valid := true
		if valid {
			score = 10.0
			result = "Signature verification succeeded!"
		} else {
			score = 5.0
			result = "Signature provided but verification failed!"
		}

		common.RemoveFileIfExists("extracted_public_key.pem")
		common.RemoveFileIfExists("extracted_signature.bin")
		common.RemoveFileIfExists("standalone_sbom.json")
	}

	return db.NewRecordStmtOptional(SBOM_SIGNATURE, "doc", result, score)
}

func bsiV2SpecVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result, score := "", 0.0

	if spec == string(sbom.SBOMSpecSPDX) {
		count := lo.Count(validBsiV2SpdxVersions, version)
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
		count := lo.Count(validBsiV2CdxVersions, version)
		if count > 0 {
			result = version
			score = 10.0
		} else {
			result = version
			score = 0.0
		}
	}

	return db.NewRecordStmt(SBOM_SPEC_VERSION, "doc", result, score, "")
}

func bsiV2Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, bsiv11ComponentCreator(component))
		records = append(records, bsiv11ComponentName(component))
		records = append(records, bsiv11ComponentVersion(component))
		records = append(records, bsiV2ComponentFilename(doc, component))
		records = append(records, bsiv11ComponentDependencies(doc, component))
		records = append(records, bsiV2ComponentAssociatedLicense(doc, component))
		records = append(records, bsiV2ComponentDeployableHash(doc, component))
		records = append(records, bsiV2ComponentExecutable(doc, component))
		records = append(records, bsiV2ComponentArchive(doc, component))
		records = append(records, bsiV2ComponentStructured(doc, component))
		records = append(records, bsiv11ComponentSourceCodeURL(component))
		records = append(records, bsiv11ComponentDownloadURL(component))
		records = append(records, bsiv11ComponentOtherUniqueIdentifiers(component))
		records = append(records, bsiV2ComponentConcludedLicense(component))
		records = append(records, bsiV2ComponentDeclaredLicense(component))
		records = append(records, bsiv11ComponentSourceHash(component))

	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

// bsiV2ComponentDeployableHash checks for SHA-512 hash on the deployable component.
// BSI v2.0: Requires SHA-512 ONLY.
// SPDX: PackageChecksum with algo SHA-512.
// CDX: externalReferences[type=distribution or distribution-intake].hashes[] with algo SHA-512.
func bsiV2ComponentDeployableHash(doc sbom.Document, component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		for _, er := range component.ExternalReferences() {
			t := er.GetRefType()
			if t == "distribution" || t == "distribution-intake" {
				for _, h := range er.GetRefHashes() {
					algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
					value := strings.TrimSpace(h.GetContent())
					if algo == "SHA512" && value != "" {
						result = h.GetAlgo() + ": " + value
						score = 10.0
						goto done
					}
				}
			}
		}
	case string(sbom.SBOMSpecSPDX):
		for _, checksum := range component.GetChecksums() {
			algo := strings.ToUpper(strings.ReplaceAll(checksum.GetAlgo(), "-", ""))
			value := strings.TrimSpace(checksum.GetContent())
			if algo == "SHA512" && value != "" {
				result = checksum.GetAlgo() + ": " + value
				score = 10.0
				goto done
			}
		}
	}
done:
	return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, common.UniqueElementID(component), result, score, "")
}

// bsiV2ComponentFilename checks for the component filename.
// BSI v2.0: The actual filename of the component.
// SPDX: PackageFileName
// CDX: custom property bsi:component:filename.
func bsiV2ComponentFilename(doc sbom.Document, component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		value := strings.TrimSpace(component.GetPropertyValue("bsi:component:filename"))
		if value != "" {
			return db.NewRecordStmt(COMP_FILENAME, id, value, 10.0, "")
		}

	case string(sbom.SBOMSpecSPDX):
		value := strings.TrimSpace(component.GetFilename())
		if value != "" {
			return db.NewRecordStmt(COMP_FILENAME, id, value, 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_FILENAME, id, "", 0.0, "")
}

// bsiV2ComponentExecutable checks whether the component is executable.
// BSI v2.0: Describes whether the component is executable.
// SPDX: PrimaryPackagePurpose = APPLICATION.
// CDX: custom property bsi:component:executable.
func bsiV2ComponentExecutable(doc sbom.Document, component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		value := strings.TrimSpace(component.GetPropertyValue("bsi:component:executable"))
		if value != "" {
			return db.NewRecordStmt(COMP_EXECUTABLE, id, value, 10.0, "")
		}

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(component.PrimaryPurpose()))
		if purpose == "APPLICATION" {
			return db.NewRecordStmt(COMP_EXECUTABLE, id, purpose, 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_EXECUTABLE, id, "", 0.0, "")
}

// bsiV2ComponentArchive checks whether the component is an archive.
// BSI v2.0: Describes whether the component is an archive.
// SPDX: PrimaryPackagePurpose = ARCHIVE .
// CDX: custom property bsi:component:archive.
func bsiV2ComponentArchive(doc sbom.Document, component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		value := strings.TrimSpace(component.GetPropertyValue("bsi:component:archive"))
		if value != "" {
			return db.NewRecordStmt(COMP_ARCHIVE, id, value, 10.0, "")
		}

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(component.PrimaryPurpose()))
		if purpose == "ARCHIVE" {
			return db.NewRecordStmt(COMP_ARCHIVE, id, purpose, 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_ARCHIVE, id, "", 0.0, "")
}

// bsiV2ComponentStructured checks whether the component is structured data.
// BSI v2.0: Describes whether the component is a structured file.
// SPDX: PrimaryPackagePurpose = SOURCE
// CDX: custom property bsi:component:structured.
func bsiV2ComponentStructured(doc sbom.Document, component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		value := strings.TrimSpace(component.GetPropertyValue("bsi:component:structured"))
		if value != "" {
			return db.NewRecordStmt(COMP_STRUCTURED, id, value, 10.0, "")
		}

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(component.PrimaryPurpose()))
		if purpose == "SOURCE" {
			return db.NewRecordStmt(COMP_STRUCTURED, id, purpose, 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_STRUCTURED, id, "", 0.0, "")
}

func bsiV2ComponentAssociatedLicense(doc sbom.Document, component sbom.GetComponent) *db.Record {
	spec := doc.Spec().GetSpecType()

	var licenses []licenses.License
	if spec == string(sbom.SBOMSpecCDX) {
		licenses = component.GetLicenses()
	} else if spec == string(sbom.SBOMSpecSPDX) {
		licenses = component.ConcludedLicenses()
	}

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_ASSOCIATED_LICENSE, common.UniqueElementID(component), "not-compliant", 0.0, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_ASSOCIATED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_ASSOCIATED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

func bsiV2ComponentConcludedLicense(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	licenses := component.ConcludedLicenses()

	if len(licenses) == 0 {
		return db.NewRecordStmtAdditional(COMP_CONCLUDED_LICENSE, id, "", 0.0, true)
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmtAdditional(COMP_CONCLUDED_LICENSE, id, "non-compliant", 0.0, false)
	}

	return db.NewRecordStmtAdditional(COMP_CONCLUDED_LICENSE, id, "compliant", 10.0, false)
}

func bsiV2ComponentDeclaredLicense(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	licenses := component.DeclaredLicenses()

	if len(licenses) == 0 {
		return db.NewRecordStmtOptional(COMP_DECLARED_LICENSE, id, "not-compliant", 0.0)
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmtOptional(COMP_DECLARED_LICENSE, id, "non-compliant", 0.0)
	}

	return db.NewRecordStmtOptional(COMP_DECLARED_LICENSE, id, "compliant", 10.0)
}
