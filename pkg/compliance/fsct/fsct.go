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
	"slices"
	"sort"
	"strings"
	"time"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
)

func Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string, coloredOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("fsct compliance")

	dtb := db.NewDB()

	// SBOM Level
	dtb.AddRecord(SBOMAuthor(doc))
	dtb.AddRecord(SBOMTimestamp(doc))
	dtb.AddRecord(SBOMType(doc)) // optional
	dtb.AddRecord(SBOMPrimaryComponent(doc))

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

// FSCT Minimum Expected:
//   - An SBOM MUST list the entity that authored the SBOM data.
//   - The author must be a person, organization, or project team.
//
// FSCT Recommended Practice:
// - The SBOM author is declared.
// - The tool(s) used to generate the SBOM are also declared (in addition to the author).
//
// Mappings:
//   - SPDX: CreationInfo.Creators of type "Person" or "Organization"
//     (Tools may be declared separately using "Tool")
//   - CycloneDX: metadata.authors (author entity),
//     metadata.tools (SBOM generation tools)
//
// Accepted Author Attributes (for Minimum Expected):
// - Name
// - Email address
// - Website / URL
// - Other contact information (e.g., phone number)
//
// Notes:
// - Declaring a tool without an author does NOT satisfy FSCT Minimum Expected.
// - Tool information enhances maturity but never replaces the Author requirement.
func SBOMAuthor(doc sbom.Document) *db.Record {
	var score float64
	var maturity, result string

	// --- Check authors (FSCT Minimum Expected) ---
	authorStr, authorPresent := "", false
	if a := doc.Authors(); a != nil {
		authorStr, authorPresent = checkAuthors(a)
	}

	// Minimum Expected not met
	if !authorPresent {
		return db.NewRecordStmt(SBOM_AUTHOR, "doc", "SBOM author not declared", 0.0, "Non-Compliant")
	}

	authorItems := strings.Split(authorStr, "; ")

	authorBlock := formatDeclaredBlock(
		"AUTHORS DECLARED",
		authorItems,
	)

	// --- Check tools (FSCT Recommended Practice) ---
	toolStr, toolPresent := "", false
	var toolItems []string

	if t := doc.Tools(); t != nil {
		toolStr, toolPresent = checkTools(t)
		if toolPresent {
			toolItems = strings.Split(toolStr, "; ")
		}
	}

	// --- Minimum Expected ---
	score = 10.0
	maturity = "Minimum Expected"
	result = authorBlock

	// --- Recommended Practice (authors + tools) ---
	if toolPresent {
		toolBlock := formatDeclaredBlock(
			"TOOLS DECLARED",
			toolItems,
		)

		score = 12.0
		maturity = "Recommended Practice"

		result = authorBlock + " | " + toolBlock
	}

	return db.NewRecordStmt(SBOM_AUTHOR, "doc", result, score, maturity)
}

func formatDeclaredBlock(title string, items []string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("%s: ", title))

	for i, item := range items {
		b.WriteString(fmt.Sprintf("(%d) %s", i+1, item))
	}

	return strings.TrimRight(b.String(), "\n")
}

func checkAuthors(authors []sbom.GetAuthor) (string, bool) {
	var result []string

	for _, author := range authors {

		// FSCT: tools are NOT valid authors
		if strings.EqualFold(author.GetType(), "tool") {
			continue
		}

		name := strings.TrimSpace(author.GetName())
		email := strings.TrimSpace(author.GetEmail())
		phone := strings.TrimSpace(author.GetPhone())

		// FSCT minimum: author must be identifiable in some way
		if name == "" && email == "" && phone == "" {
			continue
		}

		var parts []string

		if name != "" {
			parts = append(parts, name)
		}

		var contactDetails []string
		if email != "" {
			contactDetails = append(contactDetails, email)
		}

		if phone != "" {
			contactDetails = append(contactDetails, phone)
		}

		if len(contactDetails) > 0 {
			parts = append(parts, "("+strings.Join(contactDetails, ", ")+")")
		}

		result = append(result, strings.Join(parts, " "))
	}

	if len(result) == 0 {
		return "", false
	}

	return strings.Join(result, "; "), true
}

func checkTools(tools []sbom.GetTool) (string, bool) {
	var result []string

	for _, tool := range tools {
		if name := tool.GetName(); name != "" {
			if version := tool.GetVersion(); version != "" {
				result = append(result, name+"-"+version)
			} else {
				result = append(result, name)
			}
		}
	}

	if len(result) == 0 {
		return "", false
	}

	return strings.Join(result, "; "), true
}

func SBOMTimestamp(doc sbom.Document) *db.Record {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", "SBOM creation timestamp not declared", 0.0, "Non-Compliant")
	}

	// Validate format (FSCT expects machine-readable timestamp)
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", "SBOM creation timestamp is not RFC3339 compliant", 0.0, "Non-Compliant")
	}

	return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", ts, 10.0, "Minimum Expected")
}

// SBOMPrimaryComponent (Compliance)
//
// FSCT Minimum Expected:
// - An SBOM MUST explicitly identify a Primary Component.
// - The Primary Component is the subject of the SBOM and the root of the dependency graph.
// - Exactly one Primary Component must be declared.
// - The Primary Component must not be inferred.
//
// Mappings:
// - SPDX: DocumentDescribes relationship
// - CycloneDX: metadata.component
//
// Notes:
// - Absence of a Primary Component makes the SBOM non-compliant with FSCT.
// - There are no Recommended or Aspirational levels for this field.
func SBOMPrimaryComponent(doc sbom.Document) *db.Record {
	primary := doc.PrimaryComp()

	if !primary.IsPresent() {
		return db.NewRecordStmt(SBOM_PRIMARY_COMPONENT, "doc", "Primary component not declared", 0.0, "Non-Compliant")
	}

	return db.NewRecordStmt(SBOM_PRIMARY_COMPONENT, "doc", primary.GetName(), 10.0, "Minimum Expected")
}

// SBOMType
// FSCT Minimum Expected:
// - SBOM Type is NOT required.
//
// FSCT Recommended Practice:
// - SBOM Type is still optional.
//
// FSCT Aspirational Goal:
//   - The SBOM should declare its type to indicate where in the software lifecycle
//     the SBOM was generated (e.g., design, source, build, deployed, runtime).
//   - Declaring SBOM Type provides context for interpretation and correlation
//     across SBOMs.
//
// FSCT Minimum Expected:
// - SBOM Type is NOT required.
//
// FSCT Recommended Practice:
// - SBOM Type is still optional.
//
// FSCT Aspirational Goal:
//   - The SBOM should declare its type to indicate where in the software lifecycle
//     the SBOM was generated (e.g., design, source, build, deployed, runtime).
//   - Declaring SBOM Type provides context for interpretation and correlation
//     across SBOMs.
func SBOMType(doc sbom.Document) *db.Record {
	lifecycles := doc.Lifecycles()

	// FSCT: SBOM Type is aspirational; absence is acceptable
	if len(lifecycles) == 0 {
		return db.NewRecordStmt(SBOM_TYPE, "doc", "SBOM type not declared; optional per FSCT", 0.0, "Minimum Expected")
	}

	// Join declared lifecycle types for explainability
	var declared []string
	for _, lc := range lifecycles {
		if strings.TrimSpace(lc) != "" {
			declared = append(declared, lc)
		}
	}

	return db.NewRecordStmt(SBOM_TYPE, "doc", strings.Join(declared, ", "), 15.0, "Aspirational")
}

func Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, fsctCompName(component))
		records = append(records, fsctCompVersion(component))
		records = append(records, fsctCompSupplier(component))
		records = append(records, fsctCompUniqIDs(component))
		records = append(records, fsctCompChecksum(component))
		records = append(records, fsctCompRelationships(doc, component))
		records = append(records, fsctCompLicense(component))
		records = append(records, fsctCompCopyright(component))
	}
	return records
}

// fsctCompName(Must)
// FSCT says:
// - The Component Name is defined as the public name for a Component defined by the Originating Supplier of the Component.
//
// Mappings:
// - For SPDX: PackageName
// - For CycloneDX: components[].name
func fsctCompName(component sbom.GetComponent) *db.Record {
	name := strings.TrimSpace(component.GetName())
	if name == "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "Component name not declared", 0.0, "Non-Compliant")
	}
	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), name, 10.0, "Minimum Expected")
}

// fsctCompVersion(Must)
// FSCT says:
// - The Version is a supplier-defined identifier that specifies an update change in the software from a previously identified version.
//
// Mappings:
// - For SPDX: PackageVersion
// - For CycloneDX: components[].version
func fsctCompVersion(component sbom.GetComponent) *db.Record {
	version := strings.TrimSpace(component.GetVersion())
	if version == "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "Component version not declared", 0.0, "Non-Compliant")
	}
	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), version, 10.0, "Minimum Expected")
}

// FSCT Minimum Expected:
//   - Each component MUST declare a Supplier.
//   - The Supplier identifies the entity that creates, defines, or identifies the component.
//   - If the upstream supplier is difficult to identify, the supplier MUST be explicitly
//     declared as "unknown".
//
// Mappings:
// - SPDX: PackageSupplier
// - CycloneDX: components[].supplier
//
// Notes:
// - Declaring "unknown" satisfies the FSCT requirement.
// - Absence of supplier information makes the component non-compliant.
// - There are no Recommended or Aspirational maturity levels for this field.
func fsctCompSupplier(component sbom.GetComponent) *db.Record {
	supplier := component.Suppliers()

	// FSCT: supplier MUST be declared (identified or explicitly unknown)
	if supplier == nil {
		return db.NewRecordStmt(COMP_SUPPLIER, common.UniqueElementID(component), "Component supplier not declared", 0.0, "Non-Compliant")
	}

	supplierResult, supplierPresent := checkSupplier(supplier)
	if !supplierPresent {
		return db.NewRecordStmt(COMP_SUPPLIER, common.UniqueElementID(component), "Component supplier not declared", 0.0, "Non-Compliant")
	}

	return db.NewRecordStmt(COMP_SUPPLIER, common.UniqueElementID(component), supplierResult, 10.0, "Minimum Expected")
}

func checkSupplier(supplier sbom.GetSupplier) (string, bool) {
	var parts []string

	name := strings.TrimSpace(supplier.GetName())
	email := strings.TrimSpace(supplier.GetEmail())
	url := strings.TrimSpace(supplier.GetURL())

	// FSCT: explicit "unknown" is a valid supplier declaration
	if strings.EqualFold(strings.ToLower(name), "unknown") {
		return "unknown", true
	}

	// Name / email
	if name != "" {
		if email != "" {
			parts = append(parts, name+", "+email)
		} else {
			parts = append(parts, name)
		}
	} else if email != "" {
		parts = append(parts, email)
	}

	// URL
	if url != "" {
		parts = append(parts, url)
	}

	// Contacts (optional identification)
	if contacts := supplier.GetContacts(); contacts != nil {
		var contactParts []string
		for _, contact := range contacts {
			cName := strings.TrimSpace(contact.GetName())
			cEmail := strings.TrimSpace(contact.GetEmail())

			if cName != "" {
				if cEmail != "" {
					contactParts = append(contactParts, cName+", "+cEmail)
				} else {
					contactParts = append(contactParts, cName)
				}
			} else if cEmail != "" {
				contactParts = append(contactParts, cEmail)
			}
		}
		if len(contactParts) > 0 {
			parts = append(parts, "("+strings.Join(contactParts, ", ")+")")
		}
	}

	if len(parts) == 0 {
		// Supplier present but not identifiable
		return "", false
	}

	return strings.Join(parts, ", "), true
}

func fsctCompUniqIDs(component sbom.GetComponent) *db.Record {
	var results []string

	// Collect any declared identifiers (FSCT does not require validation)
	for _, p := range component.GetPurls() {
		if v := strings.TrimSpace(string(p)); v != "" {
			results = append(results, v)
		}
	}

	for _, c := range component.GetCpes() {
		if v := strings.TrimSpace(string(c)); v != "" {
			results = append(results, v)
		}
	}

	for _, o := range component.OmniborIDs() {
		if v := strings.TrimSpace(string(o)); v != "" {
			results = append(results, v)
		}
	}

	for _, s := range component.Swhids() {
		if v := strings.TrimSpace(string(s)); v != "" {
			results = append(results, v)
		}
	}

	for _, id := range component.Swids() {
		if v := strings.TrimSpace(string(swid.SWID(id).String())); v != "" {
			results = append(results, v)
		}
	}

	// FSCT: at least one unique identifier MUST be declared
	if len(results) == 0 {
		return db.NewRecordStmt(COMP_UNIQ_ID, common.UniqueElementID(component), "Component unique identifier not declared", 0.0, "Non-Compliant")
	}

	result := common.WrapLongTextIntoMulti(strings.Join(results, ", "), 100)

	return db.NewRecordStmt(COMP_UNIQ_ID, common.UniqueElementID(component), result, 10.0, "Minimum Expected")
}

func fsctCompChecksum(component sbom.GetComponent) *db.Record {
	checksums := component.GetChecksums()

	// FSCT: checksum SHOULD be declared; absence is non-compliant
	if len(checksums) == 0 {
		return db.NewRecordStmt(COMP_CHECKSUM, common.UniqueElementID(component), "Component checksum not declared", 0.0, "Non-Compliant")
	}

	hashResult, _, hasStrong := checkHash(checksums)
	if strings.TrimSpace(hashResult) == "" {
		return db.NewRecordStmt(COMP_CHECKSUM, common.UniqueElementID(component), "Component checksum not declared", 0.0, "Non-Compliant")
	}

	// Recommended Practice: strong cryptographic hash present
	if hasStrong {
		return db.NewRecordStmt(COMP_CHECKSUM, common.UniqueElementID(component), hashResult, 12.0, "Recommended Practice")
	}

	return db.NewRecordStmt(COMP_CHECKSUM, common.UniqueElementID(component), hashResult, 10.0, "Minimum Expected")
}

func checkHash(checksums []sbom.GetChecksum) (string, bool, bool) {
	var (
		hasWeak   bool
		hasStrong bool
		algos     = map[string]struct{}{}
	)

	for _, checksum := range checksums {
		content := strings.TrimSpace(checksum.GetContent())
		if content == "" {
			continue
		}

		algo := normalizeAlgoName(checksum.GetAlgo())
		if algo == "" {
			continue
		}

		algos[algo] = struct{}{}

		if isStrongChecksum(algo) {
			hasStrong = true
		} else if isWeakChecksum(algo) {
			hasWeak = true
		}
	}

	if len(algos) == 0 {
		return "", false, false
	}

	var res []string
	for a := range algos {
		res = append(res, a)
	}
	sort.Strings(res)

	return strings.Join(res, ", "), hasWeak, hasStrong
}

// isWeakChecksum returns true for weak/broken hash algorithms.
// Weak algorithms (no credit):
//   - MD family: MD2, MD4, MD5, MD6
//   - SHA-1
//   - Adler-32 (non-cryptographic)
func isWeakChecksum(algo string) bool {
	switch algo {
	case "MD2", "MD4", "MD5", "MD6":
		return true
	case "SHA1":
		return true
	case "ADLER32":
		return true
	default:
		return false
	}
}

// isStrongChecksum returns true for strong hash algorithms.
// Strong algorithms (full credit):
//   - SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512
//   - SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
//   - BLAKE family: BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3
//   - Streebog family: Streebog-256, Streebog-512
func isStrongChecksum(algo string) bool {
	switch algo {
	// SHA-2 family (SHA-224 and above)
	case "SHA224", "SHA256", "SHA384", "SHA512":
		return true
	// SHA-3 family
	case "SHA3224", "SHA3256", "SHA3384", "SHA3512":
		return true
	// BLAKE family
	case "BLAKE2B256", "BLAKE2B384", "BLAKE2B512", "BLAKE3":
		return true
	// Streebog (GOST R 34.11-2012)
	case "STREEBOG256", "STREEBOG512":
		return true

	default:
		return false
	}
}

// normalizeAlgoName normalizes algorithm names for comparison.
// Handles variations from both CycloneDX and SPDX specs:
//   - CycloneDX: "SHA-256", "SHA3-256", "BLAKE2b-256", "Streebog-256"
//   - SPDX: "SHA256", "SHA3_256", "BLAKE2b-256"
//
// After normalization, "SHA-256", "SHA256", "sha_256" all become "SHA256"
func normalizeAlgoName(algo string) string {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)
	return n
}

// FSCT Relationship requirements (§2.2.2.6):
//
// None:
// - Component is unrelated to the primary component
// - OR required relationships are missing
//
// Minimum Expected:
//   - 1. Primary component
//   - 2. Direct dependencies of the primary component
//   - 3. Dependency Declareness for primary and direct dependencies is either Complete or Unknown or incomplete.
//
// Recommended Practice:
// - All baseline requirements met, AND
// - all direct deps declare their own deps AND completeness == complete
//
// Notes:
// - Transitive leaf components are valid
// - Unrelated components are out of scope
// - Completeness is scoped to immediate upstream dependencies only
func fsctCompRelationships(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "primary component not declared", 0.0, "Non-Compliant")
	}

	primaryID := primary.GetID()
	primaryDeps := doc.GetDirectDependencies(primaryID, "DEPENDS_ON")

	// Case 1: Primary Component
	if compID == primaryID {
		agg := getCompleteness(doc, primaryID)

		// no dependencies --> check completeness declaration
		if agg == sbom.AggregateMissing {
			return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "dependency completeness not declared for primary component", 0.0, "Non-Compliant")
		}

		// relationship declared
		if len(primaryDeps) == 0 {
			return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "no dependencies declared; completeness explicitly stated for primary component", 10.0, "Minimum Expected")
		}

		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), fmt.Sprintf("direct dependencies declared (%d)", len(primaryDeps)), 10.0, "Minimum Expected")
	}

	// Case 2: Non-Primary Component
	// - check if it is a direct dependency of primary
	isDirect := false
	for _, dep := range primaryDeps {
		if dep.GetID() == compID {
			isDirect = true
			break
		}
	}

	if !isDirect {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "component not part of primary dependency graph", 0.0, "None")
	}

	agg := getCompleteness(doc, compID)
	if agg == sbom.AggregateMissing {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "dependency completeness not declared for direct dependency", 0.0, "Non-Compliant")
	}

	componentDeps := doc.GetDirectDependencies(compID, "DEPENDS_ON")

	// Case 3: direct dependency with own dependencies
	// - declared completeness
	if len(componentDeps) > 0 && agg == sbom.AggregateComplete {
		return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), fmt.Sprintf("dependencies declared and marked complete (%d)", len(componentDeps)), 12.0, "Recommended Practice")
	}

	return db.NewRecordStmt(COMP_RELATIONSHIP, common.UniqueElementID(component), "dependency relationship and completeness explicitly declared", 10.0, "Minimum Expected")
}

func getCompleteness(doc sbom.Document, primaryID string) sbom.CompositionAggregate {
	found := false
	for _, c := range doc.Composition() {

		// 1. SBOM-level completeness applies to all components
		if c.Scope() == sbom.ScopeGlobal {
			return c.Aggregate()
		}

		// 2. Dependency-scoped completeness
		if c.Scope() != sbom.ScopeDependencies {
			continue
		}

		if slices.Contains(c.Dependencies(), primaryID) {
			found = true
			return c.Aggregate()
		}
	}

	if !found {
		return sbom.AggregateMissing
	}

	return sbom.AggregateUnknown
}

func fsctCompLicense(component sbom.GetComponent) *db.Record {
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

func fsctCompCopyright(component sbom.GetComponent) *db.Record {
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
