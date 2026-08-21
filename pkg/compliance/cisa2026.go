// Copyright 2026 Interlynk.io
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
	"slices"
	"strings"
	"time"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

// CISA 2026 compliance check identifiers.
//nolint:revive,stylecheck
const (
	CISA2026_SBOM_DATA_FORMAT = iota + 1000
	CISA2026_SBOM_SPEC_VERSION
	CISA2026_SBOM_AUTHOR
	CISA2026_SBOM_TOOL_NAME
	CISA2026_SBOM_TOOL_VERSION
	CISA2026_SBOM_VERSION
	CISA2026_SBOM_TIMESTAMP
	CISA2026_SBOM_GENERATION_CONTEXT
	CISA2026_SBOM_RELATIONSHIPS
	CISA2026_SBOM_SIGNATURE
	CISA2026_COMP_NAME
	CISA2026_COMP_VERSION
	CISA2026_COMP_UNIQ_ID
	CISA2026_COMP_PRODUCER
	CISA2026_COMP_HASH_VALUE
	CISA2026_COMP_HASH_ALGO
	CISA2026_COMP_LICENSE
)

func cisa2026Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.cisa2026Result()")

	dtb := db.NewDB()

	// SBOM-level checks
	dtb.AddRecord(cisa2026SBOMDataFormat(doc))
	dtb.AddRecord(cisa2026SBOMSpecVersion(doc))
	dtb.AddRecord(cisa2026SBOMAuthor(doc))
	dtb.AddRecord(cisa2026SBOMToolName(doc))
	dtb.AddRecord(cisa2026SBOMToolVersion(doc))
	dtb.AddRecord(cisa2026SBOMVersion(doc))
	dtb.AddRecord(cisa2026SBOMTimestamp(doc))
	dtb.AddRecord(cisa2026SBOMGenerationContext(doc))
	dtb.AddRecord(cisa2026SBOMRelationships(doc))
	dtb.AddRecord(cisa2026SBOMSignature(doc))

	// Component-level checks
	dtb.AddRecords(cisa2026Components(doc))

	if outFormat == pkgcommon.FormatJSON {
		cisa2026JSONReport(dtb, fileName)
		return
	}
	if outFormat == pkgcommon.ReportBasic {
		cisa2026BasicReport(dtb, fileName)
		return
	}
	cisa2026DetailedReport(dtb, fileName, colorOutput)
}

// 1.1 SBOM Data Format
func cisa2026SBOMDataFormat(doc sbom.Document) *db.Record {
	spec := strings.TrimSpace(doc.Spec().GetSpecType())
	format := strings.TrimSpace(doc.Spec().FileFormat())

	result := spec
	if format != "" {
		result = spec + ", " + format
	}
	score := SCORE_ZERO
	if lo.Contains(validSpec, spec) && lo.Contains(validFormats, format) {
		score = SCORE_FULL
	}

	return db.NewRecordStmt(CISA2026_SBOM_DATA_FORMAT, "doc", result, score, "")
}

// 1.2 SBOM Spec Version
func cisa2026SBOMSpecVersion(doc sbom.Document) *db.Record {
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	score := SCORE_ZERO
	if ver != "" {
		score = SCORE_FULL
	}

	return db.NewRecordStmt(CISA2026_SBOM_SPEC_VERSION, "doc", ver, score, "")
}

// 1.3 SBOM Author
func cisa2026SBOMAuthor(doc sbom.Document) *db.Record {
	// 1. Explicit authors
	if authors := doc.Authors(); len(authors) > 0 {
		if val, ok := getAuthorInfo(authors); ok {
			return db.NewRecordStmt(CISA2026_SBOM_AUTHOR, "doc", val, SCORE_FULL, "")
		}
	}

	// 2. SBOM generation tools
	if tools := doc.Tools(); len(tools) > 0 {
		if val, ok := getToolInfo(tools); ok {
			return db.NewRecordStmt(CISA2026_SBOM_AUTHOR, "doc", val, SCORE_FULL, "")
		}
	}

	// 3. Supplier fallback
	if supplier := doc.Supplier(); supplier != nil {
		if val, ok := getSupplierInfo(supplier); ok {
			return db.NewRecordStmt(CISA2026_SBOM_AUTHOR, "doc", val, SCORE_FULL, "")
		}
	}

	// 4. Manufacturer fallback
	if manufacturer := doc.Manufacturer(); manufacturer != nil {
		if val, ok := getManufacturerInfo(manufacturer); ok {
			return db.NewRecordStmt(CISA2026_SBOM_AUTHOR, "doc", val, SCORE_FULL, "")
		}
	}

	return db.NewRecordStmt(CISA2026_SBOM_AUTHOR, "doc", "", SCORE_ZERO, "")
}

// 1.4 SBOM Tool Name
func cisa2026SBOMToolName(doc sbom.Document) *db.Record {
	var results []string

	if tools := doc.Tools(); tools != nil {
		for _, tool := range tools {
			name := strings.TrimSpace(tool.GetName())
			if name != "" {
				results = append(results, name)
			}
		}
	}

	result := strings.Join(lo.Uniq(results), "; ")
	if len(results) > 0 {
		return db.NewRecordStmt(CISA2026_SBOM_TOOL_NAME, "doc", result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(CISA2026_SBOM_TOOL_NAME, "doc", "", SCORE_ZERO, "")
}

// 1.5 SBOM Tool Version
func cisa2026SBOMToolVersion(doc sbom.Document) *db.Record {
	var results []string

	if tools := doc.Tools(); tools != nil {
		for _, tool := range tools {
			version := strings.TrimSpace(tool.GetVersion())
			if version != "" {
				results = append(results, version)
			}
		}
	}

	result := strings.Join(lo.Uniq(results), "; ")
	if len(results) > 0 {
		return db.NewRecordStmt(CISA2026_SBOM_TOOL_VERSION, "doc", result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(CISA2026_SBOM_TOOL_VERSION, "doc", "", SCORE_ZERO, "")
}

// 1.6 SBOM Version
func cisa2026SBOMVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()

	if spec == string(sbom.SBOMSpecCDX) {
		uri := strings.TrimSpace(doc.Spec().GetURI())
		parts := strings.Split(uri, "/")
		if len(parts) >= 2 && strings.TrimSpace(parts[len(parts)-1]) != "" {
			return db.NewRecordStmt(CISA2026_SBOM_VERSION, "doc", uri, SCORE_FULL, "")
		}
		return db.NewRecordStmt(CISA2026_SBOM_VERSION, "doc", "", SCORE_ZERO, "")
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		return db.NewRecordStmtOptional(CISA2026_SBOM_VERSION, "doc", "", SCORE_ZERO)
	}

	return db.NewRecordStmt(CISA2026_SBOM_VERSION, "doc", "", SCORE_ZERO, "")
}

// 1.7 SBOM Timestamp
func cisa2026SBOMTimestamp(doc sbom.Document) *db.Record {
	result := doc.Spec().GetCreationTimestamp()
	if result == "" {
		return db.NewRecordStmt(CISA2026_SBOM_TIMESTAMP, "doc", "", SCORE_ZERO, "")
	}

	_, err := time.Parse(time.RFC3339, result)
	if err != nil {
		return db.NewRecordStmt(CISA2026_SBOM_TIMESTAMP, "doc", result, SCORE_ZERO, "")
	}
	return db.NewRecordStmt(CISA2026_SBOM_TIMESTAMP, "doc", result, SCORE_FULL, "")
}

// 1.8 SBOM Generation Context
func cisa2026SBOMGenerationContext(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == string(sbom.SBOMSpecCDX) || (spec == string(sbom.SBOMSpecSPDX) && strings.HasPrefix(ver, "3.")) {
		lifecycles := doc.Lifecycles()
		if len(lifecycles) > 0 {
			return db.NewRecordStmt(CISA2026_SBOM_GENERATION_CONTEXT, "doc", strings.Join(lifecycles, ", "), SCORE_FULL, "")
		}
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		if c := doc.Spec().GetComment(); c != "" {
			return db.NewRecordStmt(CISA2026_SBOM_GENERATION_CONTEXT, "doc", c, SCORE_FULL, "")
		}
	}

	return db.NewRecordStmt(CISA2026_SBOM_GENERATION_CONTEXT, "doc", "", SCORE_ZERO, "")
}

// 1.9 SBOM Relationships
func cisa2026SBOMRelationships(doc sbom.Document) *db.Record {
	primary := doc.PrimaryComp()

	if !primary.IsPresent() {
		return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", "", SCORE_ZERO, "")
	}

	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(directDeps) > 0 {
		return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", fmt.Sprintf("primary component declares %d top-level dependencies", len(directDeps)), SCORE_FULL, "")
	}

	for _, c := range doc.Composition() {
		if c.Scope() != sbom.ScopeDependencies {
			continue
		}
		if !slices.Contains(c.Dependencies(), primary.GetID()) {
			continue
		}

		switch c.Aggregate() {
		case sbom.AggregateComplete:
			return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", "relationships completeness: complete", SCORE_FULL, "")
		case sbom.AggregateUnknown:
			return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", "relationships completeness: unknown", SCORE_FULL, "")
		case sbom.AggregateIncomplete:
			return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", "relationships completeness: incomplete", SCORE_ZERO, "")
		}
	}

	return db.NewRecordStmt(CISA2026_SBOM_RELATIONSHIPS, "doc", "", SCORE_ZERO, "")
}

// 1.10 SBOM Signature
func cisa2026SBOMSignature(doc sbom.Document) *db.Record {
	sig := doc.Signature()
	if sig != nil && sig.GetSigValue() != "" {
		return db.NewRecordStmtOptional(CISA2026_SBOM_SIGNATURE, "doc", "SBOM digital signature is declared", SCORE_FULL)
	}
	return db.NewRecordStmtOptional(CISA2026_SBOM_SIGNATURE, "doc", "", SCORE_ZERO)
}

// Component-level checks
func cisa2026Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records = append(records, db.NewRecordStmt(CISA2026_COMP_NAME, "doc", "", SCORE_ZERO, ""))
		return records
	}

	for _, comp := range doc.Components() {
		id := common.UniqueElementID(comp)
		records = append(records, cisa2026CompName(comp, id))
		records = append(records, cisa2026CompVersion(comp, id))
		records = append(records, cisa2026CompUniqID(comp, id))
		records = append(records, cisa2026CompProducer(comp, id))
		records = append(records, cisa2026CompHashValue(comp, id))
		records = append(records, cisa2026CompHashAlgo(comp, id))
		records = append(records, cisa2026CompLicense(comp, id))
	}
	return records
}

func cisa2026CompName(comp sbom.GetComponent, id string) *db.Record {
	if result := strings.TrimSpace(comp.GetName()); result != "" {
		return db.NewRecordStmt(CISA2026_COMP_NAME, id, result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(CISA2026_COMP_NAME, id, "", SCORE_ZERO, "")
}

func cisa2026CompVersion(comp sbom.GetComponent, id string) *db.Record {
	if result := strings.TrimSpace(comp.GetVersion()); result != "" {
		return db.NewRecordStmt(CISA2026_COMP_VERSION, id, result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(CISA2026_COMP_VERSION, id, "", SCORE_ZERO, "")
}

func cisa2026CompUniqID(comp sbom.GetComponent, id string) *db.Record {
	if purls := comp.GetPurls(); len(purls) > 0 {
		val := strings.TrimSpace(string(purls[0]))
		if val != "" {
			return db.NewRecordStmt(CISA2026_COMP_UNIQ_ID, id, val, SCORE_FULL, "")
		}
	}
	if cpes := comp.GetCpes(); len(cpes) > 0 {
		val := strings.TrimSpace(string(cpes[0]))
		if val != "" {
			return db.NewRecordStmt(CISA2026_COMP_UNIQ_ID, id, val, SCORE_FULL, "")
		}
	}
	if len(comp.Swids()) > 0 {
		return db.NewRecordStmt(CISA2026_COMP_UNIQ_ID, id, comp.Swids()[0].String(), SCORE_FULL, "")
	}
	return db.NewRecordStmt(CISA2026_COMP_UNIQ_ID, id, "", SCORE_ZERO, "")
}

func cisa2026CompProducer(comp sbom.GetComponent, id string) *db.Record {
	if supplier := comp.Suppliers(); supplier != nil {
		if val, ok := getEntityIdentifier(supplier.GetName(), supplier.GetEmail(), supplier.GetURL()); ok {
			return db.NewRecordStmt(CISA2026_COMP_PRODUCER, id, val, SCORE_FULL, "")
		}
	}
	if manufacturer := comp.Manufacturer(); manufacturer != nil {
		if val, ok := getEntityIdentifier(manufacturer.GetName(), manufacturer.GetEmail(), manufacturer.GetURL()); ok {
			return db.NewRecordStmt(CISA2026_COMP_PRODUCER, id, val, SCORE_FULL, "")
		}
	}
	for _, author := range comp.Authors() {
		if val, ok := getEntityIdentifier(author.GetName(), author.GetEmail(), ""); ok {
			return db.NewRecordStmt(CISA2026_COMP_PRODUCER, id, val, SCORE_FULL, "")
		}
	}
	return db.NewRecordStmt(CISA2026_COMP_PRODUCER, id, "", SCORE_ZERO, "")
}

func cisa2026CompHashValue(comp sbom.GetComponent, id string) *db.Record {
	for _, chk := range comp.GetChecksums() {
		if val := strings.TrimSpace(chk.GetContent()); val != "" {
			return db.NewRecordStmt(CISA2026_COMP_HASH_VALUE, id, val, SCORE_FULL, "")
		}
	}
	return db.NewRecordStmt(CISA2026_COMP_HASH_VALUE, id, "", SCORE_ZERO, "")
}

func cisa2026CompHashAlgo(comp sbom.GetComponent, id string) *db.Record {
	for _, chk := range comp.GetChecksums() {
		if algo := strings.TrimSpace(chk.GetAlgo()); algo != "" {
			return db.NewRecordStmt(CISA2026_COMP_HASH_ALGO, id, algo, SCORE_FULL, "")
		}
	}
	return db.NewRecordStmt(CISA2026_COMP_HASH_ALGO, id, "", SCORE_ZERO, "")
}

func cisa2026CompLicense(comp sbom.GetComponent, id string) *db.Record {
	licenses := []string{}
	for _, l := range comp.GetLicenses() {
		if ln := l.ShortID(); ln != "" {
			licenses = append(licenses, ln)
		}
	}
	if len(licenses) > 0 {
		result := strings.Join(licenses, "; ")
		return db.NewRecordStmt(CISA2026_COMP_LICENSE, id, result, SCORE_FULL, "")
	}

	// Check declared licenses too
	for _, l := range comp.DeclaredLicenses() {
		if ln := l.ShortID(); ln != "" {
			licenses = append(licenses, ln)
		}
	}
	if len(licenses) > 0 {
		result := strings.Join(licenses, "; ")
		return db.NewRecordStmt(CISA2026_COMP_LICENSE, id, result, SCORE_FULL, "")
	}

	return db.NewRecordStmt(CISA2026_COMP_LICENSE, id, "", SCORE_ZERO, "")
}
