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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

var validOctSpdxVersions = []string{"SPDX-2.2", "SPDX-2.3"}

func octResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.craResult()")
	db := newDB()

	db.addRecord(octSpec(doc))
	db.addRecord(octSpecVersion(doc))
	db.addRecord(octSpecSpdxID(doc))
	db.addRecord(octSbomOrganization(doc))
	db.addRecord(octSbomComment(doc))
	db.addRecord(octSbomNamespace(doc))
	db.addRecord(octSbomLicense(doc))
	db.addRecord(octSbomName(doc))
	db.addRecord(octCreatedTimestamp(doc))
	db.addRecord(octSbomTool(doc))
	db.addRecord(octMachineFormat(doc))
	db.addRecord(octHumanFormat(doc))
	db.addRecords(octComponents(doc))

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
	v := doc.Spec().SpecType()
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

	return newRecordStmt(SBOM_SPEC, "SBOM DataFormat", result, score)
}

func octSpecVersion(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	version := doc.Spec().Version()

	result := ""
	score := 0.0

	if spec == "spdx" && version != "" {
		// count := lo.Count(validOctSpdxVersions, version)
		// if count > 0 {
		result = version
		score = 10.0

	} else {
		result = version
		score = 0.0
	}

	return newRecordStmt(SBOM_SPEC_VERSION, "doc", result, score)
}

func octCreatedTimestamp(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	score := 0.0
	result := doc.Spec().CreationTimestamp()

	if spec == "spdx" && result != "" {
		score = 10.0
	} else {
		score = 0.0
	}

	return newRecordStmt(SBOM_TIMESTAMP, "doc", result, score)
}

func octSpecSpdxID(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	spdxid := doc.Spec().SpdxID()

	result := ""
	score := 0.0

	if spec == "spdx" && spdxid != "" {
		result = spdxid
		score = 10.0
	} else {
		result = spdxid
		score = 0.0
	}

	return newRecordStmt(SBOM_SPDXID, "doc", result, score)
}

func octSbomOrganization(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	org := doc.Spec().Organization()

	result := ""
	score := 0.0

	if spec == "spdx" && org != "" {
		result = org
		score = 10.0
	} else {
		result = org
		score = 0.0
	}
	return newRecordStmt(SBOM_ORG, "SBOM Build Information", result, score)
}

func octSbomComment(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	comment := doc.Spec().Comment()

	result := ""
	score := 0.0

	if spec == "spdx" && comment != "" {
		result = comment
		score = 10.0
	} else {
		result = comment
		score = 0.0
	}

	return newRecordStmt(SBOM_COMMENT, "doc", result, score)
}

func octSbomNamespace(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	ns := doc.Spec().Namespace()
	result := ""
	score := 0.0

	if spec == "spdx" && ns != "" {
		result = ns
		score = 10.0
	} else {
		result = ns
		score = 0.0
	}

	return newRecordStmt(SBOM_NAMESPACE, "doc", result, score)
}

func octSbomLicense(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	var results []string
	licenses := doc.Spec().Licenses()
	for _, x := range licenses {
		results = append(results, x.Name())
	}

	result := ""
	score := 0.0

	if spec == "spdx" && results != nil {
		result = strings.Join(results, ", ")
		score = 10.0
	} else {
		result = strings.Join(results, ", ")
		score = 0.0
	}

	return newRecordStmt(SBOM_LICENSE, "doc", result, score)
}

func octSbomName(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	name := doc.Spec().Name()

	result := ""
	score := 0.0

	if spec == "spdx" && name != "" {
		result = name
		score = 10.0
	} else {
		result = name
		score = 0.0
	}

	return newRecordStmt(SBOM_NAME, "doc", result, score)
}

func octSbomTool(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	result := doc.Tools()
	y := ""

	for _, x := range result {
		y = x.Name()
	}

	score := 0.0

	if spec == "spdx" && result != nil {
		score = 10.0
	} else {
		score = 0.0
	}
	return newRecordStmt(SBOM_TOOL, "SBOM Build Information", y, score)
}

func octMachineFormat(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	fileFormat := doc.Spec().FileFormat()
	result := ""
	score := 0.0

	if spec == "spdx" && fileFormat == "json" || fileFormat == "tag-value" {
		result = spec + ", " + fileFormat
		score = 10.0
	} else {
		result = spec + fileFormat
		score = 0.0
	}
	return newRecordStmt(SBOM_MACHINE_FORMAT, "Machine Readable Data Format", result, score)
}

func octHumanFormat(doc sbom.Document) *record {
	spec := doc.Spec().SpecType()
	fileFormat := doc.Spec().FileFormat()
	result := ""
	score := 0.0

	if spec == "spdx" && fileFormat == "json" || fileFormat == "tag-value" {
		result = fileFormat
		score = 10.0
	} else {
		result = fileFormat
		score = 0.0
	}
	return newRecordStmt(SBOM_HUMAN_FORMAT, "Human Readable Data Format", result, score)
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
	records = append(records, newRecordStmt(PACK_INFO, "doc", "present", 10.0))
	return records
}

func octPackageName(component sbom.Component) *record {
	result := component.Name()

	if result != "" {
		return newRecordStmt(PACK_NAME, component.ID(), result, 10.0)
	}

	return newRecordStmt(PACK_NAME, component.ID(), "", 0.0)
}

func octPackageSpdxID(component sbom.Component) *record {
	result := component.SpdxID()
	if result != "" {
		return newRecordStmt(PACK_SPDXID, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_SPDXID, component.ID(), result, 0.0)
}

func octPackageVersion(component sbom.Component) *record {
	result := component.Version()

	if result != "" {
		return newRecordStmt(PACK_VERSION, component.ID(), result, 10.0)
	}

	return newRecordStmt(PACK_VERSION, component.ID(), "", 0.0)
}

func octPackageSupplier(component sbom.Component) *record {
	supplier := component.Supplier()
	var results []string

	if supplier != nil {
		if supplier.Email() != "" {
			results = append(results, supplier.Email())
		}
	}
	result := strings.Join(results, ", ")

	if result != "" {
		return newRecordStmt(PACK_SUPPLIER, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_SUPPLIER, component.ID(), "", 0.0)
}

func octPackageDownloadUrl(component sbom.Component) *record {
	result := component.DownloadLocationUrl()

	if result != "" {
		return newRecordStmt(PACK_DOWNLOAD_URL, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_DOWNLOAD_URL, component.ID(), "", 0.0)
}

func octPackageFileAnalyzed(component sbom.Component) *record {
	result := component.FileAnalyzed()
	if result {
		return newRecordStmt(PACK_FILE_ANALYZED, component.ID(), "yes", 10.0)
	}

	return newRecordStmt(PACK_FILE_ANALYZED, component.ID(), "no", 0.0)
}

func octPackageHash(component sbom.Component) *record {
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

	return newRecordStmt(PACK_HASH, component.ID(), result, score)
}

func octPackageConLicense(component sbom.Component) *record {
	result := component.PackageLicenseConcluded()
	if result != "" {
		if result == "NOASSERTION" || result == "NONE" {
			return newRecordStmt(PACK_LICENSE_CON, component.ID(), result, 0.0)
		}
		return newRecordStmt(PACK_LICENSE_CON, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_LICENSE_CON, component.ID(), "", 0.0)
}

func octPackageDecLicense(component sbom.Component) *record {
	result := component.PackageLicenseDeclared()
	if result != "" {
		if result == "NOASSERTION" || result == "NONE" {
			return newRecordStmt(PACK_LICENSE_DEC, component.ID(), result, 0.0)
		}
		return newRecordStmt(PACK_LICENSE_DEC, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_LICENSE_DEC, component.ID(), "", 0.0)
}

func octPackageCopyright(component sbom.Component) *record {
	result := component.CopyRight()

	if result != "" {
		if result == "NOASSERTION" || result == "NONE" {
			return newRecordStmt(PACK_COPYRIGHT, component.ID(), result, 0.0)
		}
		return newRecordStmt(PACK_COPYRIGHT, component.ID(), result, 10.0)
	}
	return newRecordStmt(PACK_COPYRIGHT, component.ID(), "", 0.0)
}

func octPackageExternalRefs(component sbom.Component) *record {
	result := ""
	score := 0.0

	extRefs := component.ExternalReferences()
	totalElements := 0
	containPurlElement := 0

	for _, extRef := range extRefs {
		totalElements++
		result = extRef.RefType()
		if result == "purl" {
			containPurlElement++
		}
	}
	if containPurlElement != 0 {
		score = (float64(containPurlElement) / float64(totalElements)) * 10.0
		x := fmt.Sprintf(":(%d/%d)", containPurlElement, totalElements)
		result = result + x
	}
	return newRecordStmt(PACK_EXT_REF, component.ID(), result, score)
}
