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
	"fmt"
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

var (
	CompIDWithName                          = make(map[string]string)
	ComponentList                           = make(map[string]bool)
	GetAllPrimaryCompDependencies           []string
	RelationshipProvidedForPrimaryComp      bool
	ValidRelationshipProvidedForPrimaryComp bool
	GetAllPrimaryDependenciesByName         = []string{}
)

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
		records = append(records, fsctPackageDependencies(doc, component))
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

func fsctPackageDependencies(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()
	result := ""
	maturity := "None"

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 0.0, maturity)
	}

	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	if primary.GetID() == compID {
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
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 0.0, "None")
	}

	// chck if component is a direct dependency of primary
	isComponentDirectDepOfPrimary := false

	for _, dep := range primaryDeps {
		if dep.GetID() == compID {
			isComponentDirectDepOfPrimary = true
			break
		}
	}

	if !isComponentDirectDepOfPrimary {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 0.0, "None")
	}

	componentDeps := doc.GetDirectDependencies(compID, "DEPENDS_ON")

	// Case 2: Dependency of primary with own dependencies → Recommended
	if len(componentDeps) > 0 {
		names := make([]string, 0, len(componentDeps))

		for _, dep := range componentDeps {
			name := strings.TrimSpace(dep.GetName())
			if name != "" {
				names = append(names, name)
			}
		}
		fmt.Println("TRUE")
		result = strings.Join(names, ", ")
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 12.0, "Recommended")
	}

	// case:3 Dependency of primary with no own dependencies → Minimum
	return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), result, 10.0, "Minimum")
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
