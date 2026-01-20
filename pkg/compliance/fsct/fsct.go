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

package fsct

import (
	"context"
	"slices"
	"strings"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

func Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string, coloredOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("fsct compliance")

	dtb := db.NewDB()

	// SBOM Level
	dtb.AddRecord(SbomAuthor(doc))
	dtb.AddRecord(SbomTimestamp(doc))
	dtb.AddRecord(SbomType(doc))
	dtb.AddRecord(SbomPrimaryComponent(doc))

	// component Level
	dtb.AddRecords(Components(doc))

	if outFormat == pkgcommon.FormatJSON {
		fsctJSONReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		fsctBasicReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		fsctDetailedReport(dtb, fileName, coloredOutput)
	}
}

func SbomPrimaryComponent(doc sbom.Document) *db.Record {
	result, score, maturity := "", 0.0, "None"

	// waiting for NTIA to get merged
	primary := doc.PrimaryComp().IsPresent()

	if primary {
		result = doc.PrimaryComp().GetName()
		score = 10.0
		maturity = "Minimum"
	}
	return db.NewRecordStmt(SBOM_PRIMARY_COMPONENT, "doc", result, score, maturity)
}

func SbomType(doc sbom.Document) *db.Record {
	result, score, maturity := "", 0.0, "None"

	lifecycles := doc.Lifecycles()

	// get the first element of the lifecycles slice.
	if firstLifecycle, ok := lo.First(lifecycles); ok && firstLifecycle != "" {
		score = 15.0
		maturity = "Aspirational"
		result = firstLifecycle
	}

	return db.NewRecordStmt(SBOM_TYPE, "doc", result, score, maturity)
}

func SbomTimestamp(doc sbom.Document) *db.Record {
	result, score, maturity := "", 0.0, "None"

	if result = doc.Spec().GetCreationTimestamp(); result != "" {
		if _, isTimeCorrect := common.CheckTimestamp(result); isTimeCorrect {
			score = 10.0
			maturity = "Minimum"
		}
	}
	return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", result, score, maturity)
}

func SbomAuthor(doc sbom.Document) *db.Record {
	result, score, maturity := "", 0.0, ""
	authorPresent, toolPresent := false, false
	toolResult, authorResult := "", ""

	// Check for tools
	if tools := doc.Tools(); tools != nil {
		toolResult, toolPresent = common.CheckTools(tools)
	}

	// Check for authors
	if authors := doc.Authors(); authors != nil {
		authorResult, authorPresent = common.CheckAuthors(authors)
	}

	// Determine maturity level using switch
	switch {
	case authorPresent && toolPresent:
		score = 12.0
		maturity = "Recommended"
		result = authorResult + ", " + toolResult
	case authorPresent:
		score = 10.0
		maturity = "Minimum"
		result = authorResult
	case toolPresent:
		score = 0.0
		maturity = "None"
		result = toolResult
	default:
		score = 0.0
		maturity = "None"
	}

	return db.NewRecordStmt(SBOM_AUTHOR, "doc", result, score, maturity)
}

func Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, fsctPackageName(component))
		records = append(records, fsctPackageVersion(component))
		records = append(records, fsctPackageSupplier(component))
		records = append(records, fsctPackageUniqIDs(component))
		records = append(records, fsctPackageHash(doc, component))
		records = append(records, fsctPackageRelationships(doc, component))
		records = append(records, fsctPackageLicense(component))
		records = append(records, fsctPackageCopyright(component))
	}
	return records
}

func fsctPackageName(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, "None"

	if result = component.GetName(); result != "" {
		score = 10.0
		maturity = "Minimum"
	}
	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, score, maturity)
}

func fsctPackageVersion(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, "None"

	if result = component.GetVersion(); result != "" {
		score = 10.0
		maturity = "Minimum"
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, score, maturity)
}

func fsctPackageSupplier(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, ""
	supplierResult, supplierPresent := "", false

	if supplier := component.Suppliers(); supplier != nil {
		supplierResult, supplierPresent = common.CheckSupplier(supplier)
	}

	// Determine maturity level using switch
	switch {
	case supplierPresent:
		score = 10.0
		maturity = "Minimum"
		result = supplierResult
	default:
		score = 0.0
		maturity = "None"
	}

	return db.NewRecordStmt(COMP_SUPPLIER, common.UniqueElementID(component), result, score, maturity)
}

func fsctPackageUniqIDs(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, "None"
	uniqIDCount := 0
	uniqIDResults := []string{}

	if purl := component.GetPurls(); len(purl) > 0 {
		if uniqIDResult, uniqIDPresent := common.CheckPurls(purl); uniqIDPresent {
			uniqIDCount++
			uniqIDResult = common.WrapLongTextIntoMulti(uniqIDResult, 100)
			uniqIDResults = append(uniqIDResults, uniqIDResult)
		}
	}
	if cpe := component.GetCpes(); len(cpe) > 0 {
		if uniqIDResult, uniqIDPresent := common.CheckCpes(cpe); uniqIDPresent {
			uniqIDCount++
			uniqIDResult = common.WrapLongTextIntoMulti(uniqIDResult, 100)
			uniqIDResults = append(uniqIDResults, uniqIDResult)
		}
	}
	if omni := component.OmniborIDs(); len(omni) > 0 {
		if uniqIDResult, uniqIDPresent := common.CheckOmnibor(omni); uniqIDPresent {
			uniqIDCount++
			uniqIDResult = common.WrapLongTextIntoMulti(uniqIDResult, 100)
			uniqIDResults = append(uniqIDResults, uniqIDResult)
		}
	}
	if swhid := component.Swhids(); len(swhid) > 0 {
		if uniqIDResult, uniqIDPresent := common.CheckSwhid(swhid); uniqIDPresent {
			uniqIDCount++
			uniqIDResult = common.WrapLongTextIntoMulti(uniqIDResult, 100)
			uniqIDResults = append(uniqIDResults, uniqIDResult)
		}
	}
	if swids := component.Swids(); len(swids) > 0 {
		if uniqIDResult, uniqIDPresent := common.CheckSwid(swids); uniqIDPresent {
			uniqIDCount++
			uniqIDResult = common.WrapLongTextIntoMulti(uniqIDResult, 100)
			uniqIDResults = append(uniqIDResults, uniqIDResult)
		}
	}

	if uniqIDCount > 0 {
		score = 10.0
		maturity = "Minimum"
		result = strings.Join(uniqIDResults, ", ")
	}
	return db.NewRecordStmt(COMP_UNIQ_ID, common.UniqueElementID(component), result, score, maturity)
}

func fsctPackageHash(doc sbom.Document, component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, ""
	hashResult, lowAlgoHashPresent, highAlgoHashPresent := "", false, false
	var checksums []sbom.GetChecksum
	var isPrimaryComp bool

	primaryComp := doc.PrimaryComp().GetID()
	checksums = component.GetChecksums()

	if strings.Contains(primaryComp, component.GetSpdxID()) {
		isPrimaryComp = true
	}

	if checksums != nil {
		hashResult, lowAlgoHashPresent, highAlgoHashPresent = common.CheckHash(checksums)
	}

	switch {
	case hashResult != "" && isPrimaryComp && highAlgoHashPresent:
		score = 12.0
		maturity = "Recommended"
		result = hashResult
	case hashResult != "" && (highAlgoHashPresent || lowAlgoHashPresent):
		score = 10.0
		maturity = "Minimum"
		result = hashResult
	default:
		score = 0.0
		maturity = "None"
	}

	return db.NewRecordStmt(COMP_CHECKSUM, common.UniqueElementID(component), result, score, maturity)
}

// FSCT Relationship requirements (§2.2.2.6):
//
// None:
// - Component is unrelated to the primary component
// - OR required relationships are missing
//
// Minimum Expected:
// - Relationships declared for:
//   - Primary component
//   - Direct dependencies of the primary component
//
// - Leaf dependencies are valid
// - Dependency completeness may be Unknown or Complete
//
// Recommended Practice:
// - Relationships declared for all included components
// - For a direct dependency of primary:
//   - It declares its own direct dependencies
//   - AND dependency completeness is explicitly Complete
//
// Notes:
// - Transitive leaf components are valid
// - Unrelated components are out of scope
// - Completeness is scoped to immediate upstream dependencies only
func fsctPackageRelationships(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()
	result := ""
	maturity := "None"

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "no primary component", 0.0, maturity)
	}

	// Helper function: to fetch dependency completeness for a component
	getAgg := func(id string) sbom.CompositionAggregate {
		for _, c := range doc.Composition() {

			// 1. SBOM-level completeness applies to all components
			if c.Scope() == sbom.ScopeGlobal {
				return c.Aggregate()
			}

			// 2. Dependency-scoped completeness
			if c.Scope() == sbom.ScopeDependencies &&
				slices.Contains(c.Dependencies(), id) {
				return c.Aggregate()
			}
		}
		return sbom.AggregateUnknown
	}

	primaryID := primary.GetID()
	primaryDeps := doc.GetDirectDependencies(primaryID, "DEPENDS_ON")
	primaryAgg := getAgg(compID)

	// Case 1: Primary Component
	if compID == primaryID {

		// relationship declared
		if len(primaryDeps) > 0 {
			names := make([]string, 0, len(primaryDeps))

			for _, dep := range primaryDeps {
				name := strings.TrimSpace(dep.GetName())
				if name != "" {
					names = append(names, name)
				}
			}

			result = strings.Join(names, ", ")
			return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 10.0, "Minimum")
		}

		// no dependencies --> check completeness declaration
		if primaryAgg == sbom.AggregateComplete {
			return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 10.0, "Minimum")
		}

		// nothing declared,set to none
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "no relationships declared; completeness unknown", 0.0, "None")
	}

	// Case 2: Non-Primary COmponent
	// chck if it is a direct dependency of primary
	isDirectDepOfPrimary := false
	for _, dep := range primaryDeps {
		if dep.GetID() == compID {
			isDirectDepOfPrimary = true
			break
		}
	}

	if !isDirectDepOfPrimary {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "not part of primary dependency graph", 0.0, "None")
	}

	componentDeps := doc.GetDirectDependencies(compID, "DEPENDS_ON")
	componentAgg := getAgg(compID)

	// Case 3: direct dependency with own dependencies
	// declared dependencies
	if len(componentDeps) > 0 {
		names := make([]string, 0, len(componentDeps))

		for _, dep := range componentDeps {
			name := strings.TrimSpace(dep.GetName())
			if name != "" {
				names = append(names, name)
			}
		}

		result = strings.Join(names, ", ")

		// Recommended only if completeness is explicity "complete"
		// declared completeness
		if componentAgg == sbom.AggregateComplete {
			return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 12.0, "Recommended")
		}

		// otherwise, still Minimum
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 10.0, "Minimum")
	}

	// Case 4: leaf depdency of primary with completeness declared "complete"
	switch componentAgg {
	case sbom.AggregateComplete:
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 10.0, "Minimum")

	default:
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 0.0, "None")
	}
}

func fsctPackageLicense(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, "None"

	licenses := component.GetLicenses()
	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), result, score, maturity)
	}

	hasFullName, hasIdentifier, hasText, hasURL, hasSpdx := false, false, false, false, false
	var licenseContent string

	for _, license := range licenses {
		if license.Name() != "" {
			hasFullName = true
		}
		if license.ShortID() != "" {
			result = license.ShortID()
			hasIdentifier = true
		}
		if license.Source() != "" {
			licenseContent = license.Source()
			hasText = true
		}
		if license.Source() == "spdx" {
			hasSpdx = true
		}
		// Assuming URL is part of the license source or text
		if strings.HasPrefix(license.Source(), "http") {
			hasURL = true
		}
	}
	switch {
	case hasFullName && hasIdentifier && hasText && hasURL && hasSpdx:
		score = 15.0
		maturity = "Aspirational"
	case hasFullName && hasIdentifier && (hasText || hasURL):
		score = 12.0
		maturity = "Recommended"
	default:
		score = 10
		maturity = "Minimum"

	}
	// Truncate license content to 1-2 lines
	_ = truncateContent(licenseContent, 100) // Adjust the length as needed

	return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), result, score, maturity)
}

// Helper function to truncate content
func truncateContent(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}
	return content[:maxLength] + "..."
}

func fsctPackageCopyright(component sbom.GetComponent) *db.Record {
	result, score, maturity := "", 0.0, "None"
	isCopyrightPresent := false

	if cp := component.GetCopyRight(); cp != "" {
		result, isCopyrightPresent = common.CheckCopyright(cp)
	}

	if isCopyrightPresent {
		score = 10.0
		maturity = "Minimum"
		result = truncateContent(result, 50)
	}

	return db.NewRecordStmt(COMP_COPYRIGHT, common.UniqueElementID(component), result, score, maturity)
}
