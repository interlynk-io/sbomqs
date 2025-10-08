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

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func octResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.octResult()")
	dtb := db.NewDB()

	dtb.AddRecord(octSpec(doc))
	dtb.AddRecord(octSpecVersion(doc))
	dtb.AddRecord(octSpecSpdxID(doc))
	dtb.AddRecord(octSbomComment(doc))
	dtb.AddRecord(octSbomNamespace(doc))
	dtb.AddRecord(octSbomLicense(doc))
	dtb.AddRecord(octSbomName(doc))
	dtb.AddRecord(octCreatedTimestamp(doc))
	dtb.AddRecords(octComponents(doc))
	dtb.AddRecord(octMachineFormat(doc))
	dtb.AddRecord(octHumanFormat(doc))
	dtb.AddRecord(octSbomTool(doc))
	dtb.AddRecord(octSbomOrganization(doc))
	dtb.AddRecord(octSbomDeliveryTime(doc))
	dtb.AddRecord(octSbomDeliveryMethod(doc))
	dtb.AddRecord(octSbomScope(doc))

	if outFormat == "json" {
		octJSONReport(dtb, fileName)
	}

	if outFormat == "basic" {
		octBasicReport(dtb, fileName)
	}

	if outFormat == "detailed" {
		octDetailedReport(dtb, fileName, colorOutput)
	}
}

// check document data format
func octSpec(doc sbom.Document) *db.Record {
	v := doc.Spec().GetSpecType()
	vToLower := strings.Trim(strings.ToLower(v), " ")
	result := ""
	score := 0.0

	if vToLower == string(sbom.SBOMSpecSPDX) {
		result = v
		score = 10.0
	} else {
		result = v
		score = 0
	}

	return db.NewRecordStmt(SBOM_SPEC, "SPDX Elements", result, score, "")
}

func octSpecVersion(doc sbom.Document) *db.Record {
	version := doc.Spec().GetVersion()

	result := ""
	score := 0.0

	if version != "" {
		result = version
		score = 10.0
	}
	return db.NewRecordStmt(SBOM_SPEC_VERSION, "SPDX Elements", result, score, "")
}

func octCreatedTimestamp(doc sbom.Document) *db.Record {
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
	return db.NewRecordStmt(SBOM_TIMESTAMP, "SPDX Elements", result, score, "")
}

func octSpecSpdxID(doc sbom.Document) *db.Record {
	spdxid := doc.Spec().GetSpdxID()

	result := ""
	score := 0.0

	if spdxid != "" {
		result = spdxid
		score = 10.0
	}
	return db.NewRecordStmt(SBOM_SPDXID, "SPDX Elements", result, score, "")
}

func octSbomOrganization(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if org := doc.Spec().GetOrganization(); org != "" {
		result = org
		score = 10.0
	}
	return db.NewRecordStmt(SBOM_ORG, "SPDX Elements", result, score, "")
}

func octSbomComment(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if comment := doc.Spec().GetComment(); comment != "" {
		result = comment
		score = 10.0
	}

	return db.NewRecordStmt(SBOM_COMMENT, "SPDX Elements", result, score, "")
}

func breakLongString(s string, maxLength int) []string {
	if len(s) <= maxLength {
		return []string{s}
	}

	var result []string
	for len(s) > maxLength {
		result = append(result, s[:maxLength])
		s = s[maxLength:]
	}
	result = append(result, s)
	return result
}

func octSbomNamespace(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if ns := doc.Spec().GetNamespace(); ns != "" {
		result = ns
		score = 10.0
	}
	// Break the result into multiple lines if it's too long
	brokenResult := breakLongString(result, 50)
	result = strings.Join(brokenResult, "\n")

	return db.NewRecordStmt(SBOM_NAMESPACE, "SPDX Elements", result, score, "")
}

func octSbomLicense(doc sbom.Document) *db.Record {
	var results []string
	result := ""
	score := 0.0

	if licenses := doc.Spec().GetLicenses(); licenses != nil {
		for _, x := range licenses {
			if x.Name() != "" {
				results = append(results, x.Name())
			}
		}
	}

	if results != nil {
		result = strings.Join(results, ", ")
		score = 10.0
	}

	return db.NewRecordStmt(SBOM_LICENSE, "SPDX Elements", result, score, "")
}

func octSbomName(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if name := doc.Spec().GetName(); name != "" {
		result = name
		score = 10.0
	}

	return db.NewRecordStmt(SBOM_NAME, "SPDX Elements", result, score, "")
}

func octSbomTool(doc sbom.Document) *db.Record {
	result, score, name := "", 0.0, ""

	if tools := doc.Tools(); tools != nil {
		for _, tool := range tools {
			if name = tool.GetName(); name != "" {
				result = name
				score = 10.0
				break
			}
		}
	}

	return db.NewRecordStmt(SBOM_TOOL, "SPDX Elements", result, score, "")
}

func octMachineFormat(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	result, score := "", 0.0

	if fileFormat := doc.Spec().FileFormat(); fileFormat == "json" || fileFormat == "tag-value" {
		result = spec + ", " + fileFormat
		score = 10.0
	} else {
		result = spec + ", " + fileFormat
	}
	return db.NewRecordStmt(SBOM_MACHINE_FORMAT, "SPDX Elements", result, score, "")
}

func octHumanFormat(doc sbom.Document) *db.Record {
	result, score := "", 0.0

	if fileFormat := doc.Spec().FileFormat(); fileFormat == "json" || fileFormat == "tag-value" {
		result = fileFormat
		score = 10.0
	} else {
		result = fileFormat
	}
	return db.NewRecordStmt(SBOM_HUMAN_FORMAT, "SPDX Elements", result, score, "")
}

func octSbomDeliveryMethod(_ sbom.Document) *db.Record {
	result, score := "unknown", 0.0

	return db.NewRecordStmt(SBOM_DELIVERY_METHOD, "SPDX Elements", result, score, "")
}

func octSbomDeliveryTime(_ sbom.Document) *db.Record {
	result, score := "unknown", 0.0

	return db.NewRecordStmt(SBOM_DELIVERY_TIME, "SPDX Elements", result, score, "")
}

func octSbomScope(_ sbom.Document) *db.Record {
	result, score := "unknown", 0.0

	return db.NewRecordStmt(SBOM_SCOPE, "SPDX Elements", result, score, "")
}

func octComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, octPackageName(component))
		records = append(records, octPackageSpdxID(component))
		records = append(records, octPackageVersion(component))
		records = append(records, octPackageSupplier(component))
		records = append(records, octPackageDownloadURL(component))
		records = append(records, octPackageFileAnalyzed(component))
		records = append(records, octPackageHash(component))
		records = append(records, octPackageConLicense(component))
		records = append(records, octPackageDecLicense(component))
		records = append(records, octPackageCopyright(component))
		records = append(records, octPackageExternalRefs(component))
	}
	records = append(records, db.NewRecordStmt(PACK_INFO, "SPDX Elements", "present", 10.0, ""))
	return records
}

func octPackageName(component sbom.GetComponent) *db.Record {
	if result := component.GetName(); result != "" {
		return db.NewRecordStmt(PACK_NAME, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(PACK_NAME, common.UniqueElementID(component), "", 0.0, "")
}

func octPackageSpdxID(component sbom.GetComponent) *db.Record {
	if result := component.GetSpdxID(); result != "" {
		return db.NewRecordStmt(PACK_SPDXID, common.UniqueElementID(component), result, 10.0, "")
	}
	return db.NewRecordStmt(PACK_SPDXID, common.UniqueElementID(component), "", 0.0, "")
}

func octPackageVersion(component sbom.GetComponent) *db.Record {
	if result := component.GetVersion(); result != "" {
		return db.NewRecordStmt(PACK_VERSION, common.UniqueElementID(component), result, 10.0, "")
	}
	return db.NewRecordStmt(PACK_VERSION, common.UniqueElementID(component), "", 0.0, "")
}

func octPackageSupplier(component sbom.GetComponent) *db.Record {
	if supplier := component.Suppliers().GetEmail(); supplier != "" {
		return db.NewRecordStmt(PACK_SUPPLIER, common.UniqueElementID(component), supplier, 10.0, "")
	}
	return db.NewRecordStmt(PACK_SUPPLIER, common.UniqueElementID(component), "", 0.0, "")
}

func octPackageDownloadURL(component sbom.GetComponent) *db.Record {
	if result := component.GetDownloadLocationURL(); result != "" {
		brokenResult := breakLongString(result, 50)
		result = strings.Join(brokenResult, "\n")
		return db.NewRecordStmt(PACK_DOWNLOAD_URL, common.UniqueElementID(component), result, 10.0, "")
	}
	return db.NewRecordStmt(PACK_DOWNLOAD_URL, common.UniqueElementID(component), "", 0.0, "")
}

func octPackageFileAnalyzed(component sbom.GetComponent) *db.Record {
	if result := component.GetFileAnalyzed(); result {
		return db.NewRecordStmt(PACK_FILE_ANALYZED, common.UniqueElementID(component), "yes", 10.0, "")
	}

	return db.NewRecordStmt(PACK_FILE_ANALYZED, common.UniqueElementID(component), "no", 0.0, "")
}

func octPackageHash(component sbom.GetComponent) *db.Record {
	result, score := "", 0.0
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}

	if checksums := component.GetChecksums(); checksums != nil {
		for _, checksum := range checksums {
			if lo.Count(algos, checksum.GetAlgo()) > 0 {
				result = checksum.GetContent()
				score = 10.0
				break
			}
		}
	}

	return db.NewRecordStmt(PACK_HASH, common.UniqueElementID(component), result, score, "")
}

func octPackageConLicense(component sbom.GetComponent) *db.Record {
	result := ""

	if result = component.GetPackageLicenseConcluded(); result != "" && result != "NOASSERTION" && result != "NONE" {
		return db.NewRecordStmt(PACK_LICENSE_CON, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(PACK_LICENSE_CON, common.UniqueElementID(component), result, 0.0, "")
}

func octPackageDecLicense(component sbom.GetComponent) *db.Record {
	result := ""

	if result = component.GetPackageLicenseDeclared(); result != "" && result != "NOASSERTION" && result != "NONE" {
		return db.NewRecordStmt(PACK_LICENSE_DEC, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(PACK_LICENSE_DEC, common.UniqueElementID(component), result, 0.0, "")
}

func octPackageCopyright(component sbom.GetComponent) *db.Record {
	result := ""

	if result = component.GetCopyRight(); result != "" && result != "NOASSERTION" && result != "NONE" {
		result = strings.ReplaceAll(result, "\n", " ")
		result = strings.ReplaceAll(result, "\t", " ")

		brokenResult := breakLongString(result, 50)
		result = strings.Join(brokenResult, "\n")

		return db.NewRecordStmt(PACK_COPYRIGHT, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(PACK_COPYRIGHT, common.UniqueElementID(component), result, 0.0, "")
}

func octPackageExternalRefs(component sbom.GetComponent) *db.Record {
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
	return db.NewRecordStmt(PACK_EXT_REF, common.UniqueElementID(component), result, score, "")
}
