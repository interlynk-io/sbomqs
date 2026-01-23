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

var (
	validSpec    = []string{pkgcommon.FormatCycloneDX, pkgcommon.FormatSPDX}
	validFormats = []string{pkgcommon.FormatJSON, pkgcommon.FormatXML, pkgcommon.FormatYAML, pkgcommon.FormatYML, pkgcommon.FormatTagValue}
)

// Scoring constants for NTIA compliance evaluation.
// These values represent the maximum and minimum scores for compliance checks.
// nolint
const (
	// SCORE_FULL represents the maximum score (10.0) when a compliance requirement is fully met.
	SCORE_FULL = 10.0
	// SCORE_ZERO represents the minimum score (0.0) when a compliance requirement is not met.
	SCORE_ZERO = 0.0
)

func ntiaResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ntiaResult()")

	db := db.NewDB()

	// 1. Automation Support
	db.AddRecord(ntiaMachineFormatAutomationSpec(doc))
	db.AddRecord(ntiaSBOMGenerationAutomationTool(doc))

	// 2. Required Document-level Data Fields
	db.AddRecord(ntiaSbomAuthor(doc))
	db.AddRecord(ntiaSbomCreatedTimestamp(doc))
	db.AddRecord(ntiaSBOMDependencyRelationships(doc))

	// 3. Required Component-level Data Fields
	db.AddRecords(ntiaComponents(doc))

	if outFormat == pkgcommon.FormatJSON {
		ntiaJSONReport(db, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		ntiaBasicReport(db, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		ntiaDetailedReport(db, fileName, colorOutput)
	}
}

// 1.1 Automation Support: Machine-Readable Format
func ntiaMachineFormatAutomationSpec(doc sbom.Document) *db.Record {
	score := SCORE_ZERO
	parts := []string{}

	spec := strings.TrimSpace(doc.Spec().GetSpecType())
	fileFormat := strings.TrimSpace(doc.Spec().FileFormat())

	if spec != "" {
		parts = append(parts, spec)
	}

	if fileFormat != "" {
		parts = append(parts, fileFormat)
	}

	result := strings.Join(parts, ", ")

	if lo.Contains(validSpec, spec) && lo.Contains(validFormats, fileFormat) {
		score = SCORE_FULL
	}

	if result == "" {
		result = "not declared"
	}

	return db.NewRecordStmt(SBOM_MACHINE_FORMAT, "Automation Support", result, score, "")
}

// 1.2 Automation Support: ntiaSBOMGenerationAutomationTool
func ntiaSBOMGenerationAutomationTool(doc sbom.Document) *db.Record {
	score := SCORE_ZERO
	var results []string
	hasVersionOnly := false

	if tools := doc.Tools(); tools != nil {
		for _, tool := range tools {
			name := strings.TrimSpace(tool.GetName())
			version := strings.TrimSpace(tool.GetVersion())

			switch {
			case name != "" && version != "":
				results = append(results, fmt.Sprintf("%s-%s", name, version))

			case name != "":
				results = append(results, name)

			case name == "" && version != "":
				hasVersionOnly = true
			}
		}
	}

	result := strings.Join(lo.Uniq(results), "; ")

	if len(results) > 0 {
		score = SCORE_FULL
	} else if hasVersionOnly {
		result = "SBOM tool version declared without tool name"
	} else {
		result = "no SBOM generation tool declared"
	}

	return db.NewRecordStmt(SBOM_AUTOMATION_TOOL, "Automation Support", result, score, "")
}

// 2.1 Required Document-level Data Fields: ntiaSbomAuthor
func ntiaSbomAuthor(doc sbom.Document) *db.Record {
	score := SCORE_ZERO

	// 1. Explicit authors
	if authors := doc.Authors(); len(authors) > 0 {
		if val, ok := getAuthorInfo(authors); ok {
			score = SCORE_FULL
			return db.NewRecordStmt(SBOM_CREATOR, "Required Document-level", fmt.Sprintf("author declared explicitly: %s", val), score, "")
		}
	}

	// 2. SBOM generation tools
	if tools := doc.Tools(); len(tools) > 0 {
		if val, ok := getToolInfo(tools); ok {
			score = SCORE_FULL
			return db.NewRecordStmt(SBOM_CREATOR, "Required Document-level", fmt.Sprintf("author inferred from SBOM tool: %s", val), score, "")
		}
	}

	// 3. Supplier fallback
	if supplier := doc.Supplier(); supplier != nil {
		if val, ok := getSupplierInfo(supplier); ok {
			score = SCORE_FULL
			return db.NewRecordStmt(SBOM_CREATOR, "Required Document-level", fmt.Sprintf("author inferred from supplier (fallback): %s", val), score, "")
		}
	}

	// 4. Manufacturer fallback
	if manufacturer := doc.Manufacturer(); manufacturer != nil {
		if val, ok := getManufacturerInfo(manufacturer); ok {
			score = SCORE_FULL
			return db.NewRecordStmt(SBOM_CREATOR, "Required Document-level", fmt.Sprintf("author inferred from manufacturer (fallback): %s", val), score, "")
		}
	}

	// 5. Not declared
	return db.NewRecordStmt(SBOM_CREATOR, "Required Document-level", "SBOM author absent", SCORE_ZERO, "")
}

func getAuthorInfo(authors []sbom.GetAuthor) (string, bool) {
	for _, author := range authors {
		if name := strings.TrimSpace(author.GetName()); name != "" {
			return name, true
		}

		if email := strings.TrimSpace(author.GetEmail()); email != "" {
			return email, true
		}
	}
	return "", false
}

func getToolInfo(tools []sbom.GetTool) (string, bool) {
	for _, tool := range tools {
		name := strings.TrimSpace(tool.GetName())
		version := strings.TrimSpace(tool.GetVersion())

		if name != "" && version != "" {
			return fmt.Sprintf("%s-%s", name, version), true
		}
		if name != "" {
			return name, true
		}
	}
	return "", false
}

func getSupplierInfo(supplier sbom.GetSupplier) (string, bool) {
	if supplier == nil {
		return "", false
	}
	if name := strings.TrimSpace(supplier.GetName()); name != "" {
		return name, true
	}
	if email := strings.TrimSpace(supplier.GetEmail()); email != "" {
		return email, true
	}
	if url := strings.TrimSpace(supplier.GetURL()); url != "" {
		return url, true
	}
	return "", false
}

func getManufacturerInfo(manufacturer sbom.GetManufacturer) (string, bool) {
	if manufacturer == nil {
		return "", false
	}
	if name := strings.TrimSpace(manufacturer.GetName()); name != "" {
		return name, true
	}
	if email := strings.TrimSpace(manufacturer.GetEmail()); email != "" {
		return email, true
	}
	if url := strings.TrimSpace(manufacturer.GetURL()); url != "" {
		return url, true
	}
	return "", false
}

// 2.2 Required Document-level Data Fields: ntiaSbomCreatedTimestamp
func ntiaSbomCreatedTimestamp(doc sbom.Document) *db.Record {
	score := SCORE_ZERO
	result := doc.Spec().GetCreationTimestamp()

	if result != "" {
		_, err := time.Parse(time.RFC3339, result)
		if err != nil {
			score = SCORE_ZERO
		} else {
			score = SCORE_FULL
		}
	}
	return db.NewRecordStmt(SBOM_TIMESTAMP, "SBOM Data Fields", result, score, "")
}

// 2.3 Required Document-level Data Fields: ntiaSBOMDependencyRelationships

// NTIA requires that an SBOM declare the upstream dependency relationships
// of the *primary (top-level) component*.
// - At a minimum, the SBOM must list the primary component's direct dependencies.
// - or decalrer completeness if no dependencies exist.
func ntiaSBOMDependencyRelationships(doc sbom.Document) *db.Record {
	primary := doc.PrimaryComp()

	// Primary component must be declared
	if !primary.IsPresent() {
		return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", "primary component not declared", SCORE_ZERO, "")
	}

	// 1. Check direct dependencies of primary component
	deps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(deps) > 0 {
		return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", fmt.Sprintf("primary component declares %d direct dependencies", len(deps)), SCORE_FULL, "")
	}

	// 2. No direct dependencies -> check declared completeness
	for _, c := range doc.Composition() {

		if c.Scope() != sbom.ScopeDependencies {
			continue
		}

		if !slices.Contains(c.Dependencies(), primary.GetID()) {
			continue
		}

		switch c.Aggregate() {

		case sbom.AggregateComplete:
			return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", "primary component declares dependencies completeness complete", SCORE_FULL, "")

		case sbom.AggregateUnknown:
			return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", "primary component declares dependencies completeness unknown", SCORE_FULL, "")

		case sbom.AggregateIncomplete:
			return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", "primary component declares dependencies completeness incomplete", SCORE_ZERO, "")
		}
	}

	// 3. No dependencies and no completeness declaration
	// Default NTIA interpretation: incomplete
	return db.NewRecordStmt(SBOM_DEPENDENCY_RELATIONSHIP, "Required Document-level", "no dependency relationships or completeness declared for primary component", SCORE_ZERO, "")
}

// Required component stuffs
func ntiaComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "SBOM Data Fields", "absent", SCORE_ZERO, ""))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, ntiaComponentSupplier(component))
		records = append(records, ntiaComponentName(component))
		records = append(records, ntiaComponentVersion(component))
		records = append(records, ntiaComponentOtherUniqIDs(component))
	}
	return records
}

func ntiaComponentSupplier(component sbom.GetComponent) *db.Record {
	result := ""
	score := SCORE_ZERO

	// 1. Supplier (primary)
	if supplier := component.Suppliers(); supplier != nil {
		if val, ok := getEntityIdentifier(supplier.GetName(), supplier.GetEmail(), supplier.GetURL()); ok {
			result = val
			score = SCORE_FULL
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}
	}

	// 2. Manufacturer (fallback)
	if manufacturer := component.Manufacturer(); manufacturer != nil {
		if val, ok := getEntityIdentifier(manufacturer.GetName(), manufacturer.GetEmail(), manufacturer.GetURL()); ok {
			result = val
			score = SCORE_FULL
			return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), result, score, "")
		}
	}

	// 3. Not declared
	return db.NewRecordStmt(COMP_CREATOR, common.UniqueElementID(component), "supplier not declared", SCORE_ZERO, "")
}

func getEntityIdentifier(name, email, url string) (string, bool) {
	if v := strings.TrimSpace(name); v != "" {
		return v, true
	}
	if v := strings.TrimSpace(email); v != "" {
		return v, true
	}
	if v := strings.TrimSpace(url); v != "" {
		return v, true
	}
	return "", false
}

func ntiaComponentName(component sbom.GetComponent) *db.Record {
	if result := strings.TrimSpace(component.GetName()); result != "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "", SCORE_ZERO, "")
}

func ntiaComponentVersion(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetVersion())

	if result != "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, SCORE_FULL, "")
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "", SCORE_ZERO, "")
}

func ntiaComponentOtherUniqIDs(component sbom.GetComponent) *db.Record {
	result := ""
	score := SCORE_ZERO

	// 1. Prefer PURL if present
	if purls := component.GetPurls(); len(purls) > 0 {
		val := strings.TrimSpace(string(purls[0]))
		if val != "" {
			result = common.WrapLongTextIntoMulti(val, 100)
			score = SCORE_FULL
			return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score)
		}
	}

	// 2. Fallback to CPE if present
	if cpes := component.GetCpes(); len(cpes) > 0 {
		val := strings.TrimSpace(string(cpes[0]))
		if val != "" {
			result = common.WrapLongTextIntoMulti(val, 100)
			score = SCORE_FULL
			return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score)
		}
	}

	// 3. Not present (optional per NTIA)
	return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), "no unique identifier declared", SCORE_ZERO)
}
