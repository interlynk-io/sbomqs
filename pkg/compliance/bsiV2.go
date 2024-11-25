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

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
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
	// dtb.AddRecord(bsiSbomSignature(doc))
	// dtb.AddRecord(bsiSbomLinks(doc))

	if outFormat == "json" {
		bsiV2JSONReport(dtb, fileName)
	}

	if outFormat == "basic" {
		bsiV2BasicReport(dtb, fileName)
	}

	if outFormat == "detailed" {
		bsiV2DetailedReport(dtb, fileName)
	}
}

func bsiV2Vulnerabilities(doc sbom.Document) *db.Record {
	result, score := "no-vulnerability", 10.0

	vuln := doc.Vulnerabilities()

	if vuln != nil {
		vulnId := vuln.GetID()
		if vulnId != "" {
			result = vulnId
		}
		score = 0.0
	}
	return db.NewRecordStmt(SBOM_VULNERABILITES, "doc", result, score, "")
}

func bsiV2SpecVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result, score := "", 0.0

	if spec == "spdx" {
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
	} else if spec == "cyclonedx" {
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
		records = append(records, bsiComponentLicense(component))
		records = append(records, bsiComponentDepth(doc, component))
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
		// records = append(records, bsiComponentDeclaredLicense(component))
		// records = append(records, bsiComponentConcludedLicense(component))

	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}
