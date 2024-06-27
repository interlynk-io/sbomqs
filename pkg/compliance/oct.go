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

var validOctSpdxVersions = []string{"SPDX-2.2", "SPDX-2.3"}

func octResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.octResult()")
	db := newDB()

	db.addRecord(octSpec(doc))
	db.addRecord(octSpecVersion(doc))
	db.addRecord(octSpecSpdxID(doc))
	db.addRecord(octSbomComment(doc))
	db.addRecord(octSbomNamespace(doc))
	db.addRecord(octSbomLicense(doc))
	db.addRecord(octSbomName(doc))
	db.addRecord(octCreatedTimestamp(doc))
	db.addRecords(octComponents(doc))
	db.addRecord(octMachineFormat(doc))
	db.addRecord(octHumanFormat(doc))
	db.addRecord(octSbomTool(doc))
	db.addRecord(octSbomOrganization(doc))
	db.addRecord(octSbomDeliveryTime(doc))
	db.addRecord(octSbomDeliveryMethod(doc))
	db.addRecord(octSbomScope(doc))

	if outFormat == "json" {
		octJsonReport(db, fileName)
	}

	if outFormat == "basic" {
		octBasicReport(db, fileName)
	}

	if outFormat == "detailed" {
		octDetailedReport(db, fileName)
	}
}

// check document data format
func octSpec(doc sbom.Document) *record {
	v := doc.Spec().GetSpecType()
	vToLower := strings.Trim(strings.ToLower(v), " ")
	result := ""
	score := 0.0

	if vToLower == "spdx" {
		result = v
		score = 10.0
	} else {
		result = v
		score = 0
	}

	return newRecordStmt(SBOM_SPEC, "SBOM Format", result, score)
}

func octSpecVersion(doc sbom.Document) *record {
	version := doc.Spec().GetVersion()

	result := ""
	score := 0.0

	if version != "" {
		result = version
		score = 10.0
	}
	return newRecordStmt(SBOM_SPEC_VERSION, "SPDX Elements", result, score)
}

func octCreatedTimestamp(doc sbom.Document) *record {
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
	return newRecordStmt(SBOM_TIMESTAMP, "SPDX Elements", result, score)
}

func octSpecSpdxID(doc sbom.Document) *record {
	spdxid := doc.Spec().GetSpdxID()

	result := ""
	score := 0.0

	if spdxid != "" {
		result = spdxid
		score = 10.0
	}
	return newRecordStmt(SBOM_SPDXID, "SPDX Elements", result, score)
}

func octSbomOrganization(doc sbom.Document) *record {
	result, score := "", 0.0

	if org := doc.Spec().GetOrganization(); org != "" {
		result = org
		score = 10.0
	}
	return newRecordStmt(SBOM_ORG, "SBOM Build Information", result, score)
}

func octSbomComment(doc sbom.Document) *record {
	result, score := "", 0.0

	if comment := doc.Spec().GetComment(); comment != "" {
		result = comment
		score = 10.0
	}

	return newRecordStmt(SBOM_COMMENT, "SPDX Elements", result, score)
}

func octSbomNamespace(doc sbom.Document) *record {
	result, score := "", 0.0

	if ns := doc.Spec().GetNamespace(); ns != "" {
		result = ns
		score = 10.0
	}

	return newRecordStmt(SBOM_NAMESPACE, "SPDX Elements", result, score)
}

func octSbomLicense(doc sbom.Document) *record {
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

	return newRecordStmt(SBOM_LICENSE, "SPDX Elements", result, score)
}

func octSbomName(doc sbom.Document) *record {
	result, score := "", 0.0

	if name := doc.Spec().GetName(); name != "" {
		result = name
		score = 10.0
	}

	return newRecordStmt(SBOM_NAME, "SPDX Elements", result, score)
}

func octSbomTool(doc sbom.Document) *record {
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

	return newRecordStmt(SBOM_TOOL, "SBOM Build Information", result, score)
}

func octMachineFormat(doc sbom.Document) *record {
	spec := doc.Spec().GetSpecType()
	result, score := "", 0.0

	if fileFormat := doc.Spec().FileFormat(); fileFormat == "json" || fileFormat == "tag-value" {
		result = spec + ", " + fileFormat
		score = 10.0
	} else {
		result = spec + ", " + fileFormat
	}
	return newRecordStmt(SBOM_MACHINE_FORMAT, "Machine Readable Data Format", result, score)
}

func octHumanFormat(doc sbom.Document) *record {
	result, score := "", 0.0

	if fileFormat := doc.Spec().FileFormat(); fileFormat == "json" || fileFormat == "tag-value" {
		result = fileFormat
		score = 10.0
	} else {
		result = fileFormat
	}
	return newRecordStmt(SBOM_HUMAN_FORMAT, "Human Readable Data Format", result, score)
}

func octSbomDeliveryMethod(_ sbom.Document) *record {
	result, score := "unknown", 0.0

	return newRecordStmt(SBOM_DELIVERY_METHOD, "Method of SBOM delivery", result, score)
}

func octSbomDeliveryTime(_ sbom.Document) *record {
	result, score := "unknown", 0.0

	return newRecordStmt(SBOM_DELIVERY_TIME, "Timing of SBOM delivery", result, score)
}

func octSbomScope(_ sbom.Document) *record {
	result, score := "unknown", 0.0

	return newRecordStmt(SBOM_SCOPE, "SBOM Scope", result, score)
}

func octComponents(doc sbom.Document) []*record {
	records := []*record{}

	if len(doc.Components()) == 0 {
		records := append(records, newRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, octPackageName(component))
		records = append(records, octPackageSpdxID(component))
		records = append(records, octPackageVersion(component))
		records = append(records, octPackageSupplier(component))
		records = append(records, octPackageDownloadUrl(component))
		records = append(records, octPackageFileAnalyzed(component))
		records = append(records, octPackageHash(component))
		records = append(records, octPackageConLicense(component))
		records = append(records, octPackageDecLicense(component))
		records = append(records, octPackageCopyright(component))
		records = append(records, octPackageExternalRefs(component))
	}
	records = append(records, newRecordStmt(PACK_INFO, "SPDX Elements", "present", 10.0))
	return records
}

func octPackageName(component sbom.GetComponent) *record {
	if result := component.GetName(); result != "" {
		return newRecordStmt(PACK_NAME, component.GetID(), result, 10.0)
	}
	return newRecordStmt(PACK_NAME, component.GetID(), "", 0.0)
}

func octPackageSpdxID(component sbom.GetComponent) *record {
	if result := component.GetSpdxID(); result != "" {
		return newRecordStmt(PACK_SPDXID, component.GetID(), result, 10.0)
	}
	return newRecordStmt(PACK_SPDXID, component.GetID(), "", 0.0)
}

func octPackageVersion(component sbom.GetComponent) *record {
	if result := component.GetVersion(); result != "" {
		return newRecordStmt(PACK_VERSION, component.GetID(), result, 10.0)
	}
	return newRecordStmt(PACK_VERSION, component.GetID(), "", 0.0)
}

func octPackageSupplier(component sbom.GetComponent) *record {
	if supplier := component.Suppliers().GetEmail(); supplier != "" {
		return newRecordStmt(PACK_SUPPLIER, component.GetID(), supplier, 10.0)
	}
	return newRecordStmt(PACK_SUPPLIER, component.GetID(), "", 0.0)
}

func octPackageDownloadUrl(component sbom.GetComponent) *record {
	if result := component.GetDownloadLocationUrl(); result != "" {
		return newRecordStmt(PACK_DOWNLOAD_URL, component.GetID(), result, 10.0)
	}
	return newRecordStmt(PACK_DOWNLOAD_URL, component.GetID(), "", 0.0)
}

func octPackageFileAnalyzed(component sbom.GetComponent) *record {
	if result := component.GetFileAnalyzed(); result {
		return newRecordStmt(PACK_FILE_ANALYZED, component.GetID(), "yes", 10.0)
	}

	return newRecordStmt(PACK_FILE_ANALYZED, component.GetID(), "no", 0.0)
}

func octPackageHash(component sbom.GetComponent) *record {
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

	return newRecordStmt(PACK_HASH, component.GetID(), result, score)
}

func octPackageConLicense(component sbom.GetComponent) *record {
	result := ""

	if result = component.GetPackageLicenseConcluded(); result != "" && result != "NOASSERTION" && result != "NONE" {
		return newRecordStmt(PACK_LICENSE_CON, component.GetID(), result, 10.0)
	}

	return newRecordStmt(PACK_LICENSE_CON, component.GetID(), result, 0.0)
}

func octPackageDecLicense(component sbom.GetComponent) *record {
	result := ""

	if result = component.GetPackageLicenseDeclared(); result != "" && result != "NOASSERTION" && result != "NONE" {
		return newRecordStmt(PACK_LICENSE_DEC, component.GetID(), result, 10.0)
	}

	return newRecordStmt(PACK_LICENSE_DEC, component.GetID(), result, 0.0)
}

func octPackageCopyright(component sbom.GetComponent) *record {
	result := ""

	if result = component.GetCopyRight(); result != "" && result != "NOASSERTION" && result != "NONE" {
		return newRecordStmt(PACK_COPYRIGHT, component.GetID(), result, 10.0)
	}

	return newRecordStmt(PACK_COPYRIGHT, component.GetID(), result, 0.0)
}

func octPackageExternalRefs(component sbom.GetComponent) *record {
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
	return newRecordStmt(PACK_EXT_REF, component.GetID(), result, score)
}
