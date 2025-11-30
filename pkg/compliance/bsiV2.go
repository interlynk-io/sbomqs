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
	"os"
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
	validBsiV2SpdxVersions = []string{"SPDX-2.2", "SPDX-2.3"}
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
	dtb.AddRecord(bsiSbomDepth(doc))
	dtb.AddRecord(bsiCreator(doc))
	dtb.AddRecord(bsiTimestamp(doc))
	dtb.AddRecord(bsiSbomURI(doc))
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

	return db.NewRecordStmt(SBOM_BOM_LINKS, "doc", result, score, "")
}

func bsiV2Vulnerabilities(doc sbom.Document) *db.Record {
	result, score := "no-vulnerability", 10.0

	vulns := doc.Vulnerabilities()
	var allVulnIDs []string

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
		// verify signature
		pubKey := doc.Signature().GetPublicKey()
		blob := doc.Signature().GetBlob()
		sig := doc.Signature().GetSigValue()

		pubKeyData, err := os.ReadFile(pubKey)
		if err != nil {
			return db.NewRecordStmt(SBOM_SIGNATURE, "doc", "Sig not detected!", 0.0, "")
		}

		valid, err := common.VerifySignature(pubKeyData, blob, sig)
		if err != nil {
			return db.NewRecordStmt(SBOM_SIGNATURE, "doc", "Verification failed!", 0.0, "")
		}
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

	return db.NewRecordStmt(SBOM_SIGNATURE, "doc", result, score, "")
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
		records = append(records, bsiComponentDepth(doc, component))
		records = append(records, bsiV2ComponentAssociatedLicense(doc, component))
		records = append(records, bsiComponentHash(component))
		records = append(records, bsiComponentSourceCodeURL(component))
		records = append(records, bsiComponentDownloadURL(component))
		records = append(records, bsiComponentSourceHash(component))
		records = append(records, bsiComponentOtherUniqIDs(component))
		// New Components fields
		// records = append(records, bsiComponentFilename(component))
		// records = append(records, bsiComponentExecutable(component))
		// records = append(records, bsiComponentArchive(component))
		// records = append(records, bsiComponentStructured(component))
		// records = append(records, bsiComponentOtherUniqIDs(component))
		records = append(records, bsiV2ComponentConcludedLicense(component))
		records = append(records, bsiV2ComponentDeclaredLicense(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
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
	licenses := component.ConcludedLicenses()
	score := 0.0

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "not-compliant", score, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

func bsiV2ComponentDeclaredLicense(component sbom.GetComponent) *db.Record {
	licenses := component.DeclaredLicenses()
	score := 0.0

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "not-compliant", score, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_DECLARED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}
