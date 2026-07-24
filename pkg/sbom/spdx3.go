// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/validation"
	spdx "github.com/interlynk-io/spdx-zen/model/v3.0.1"
	"github.com/interlynk-io/spdx-zen/parse"
)

type Spdx3Doc struct {
	doc              *parse.Document
	format           FileFormat
	version          FormatVersion
	ctx              context.Context
	SpdxSpec         *Specs
	spdxValidSchema  bool
	Comps            []GetComponent
	Auths            []GetAuthor
	SpdxTools        []GetTool
	Relationships    []GetRelationship
	logs             []string
	PrimaryComponent PrimaryComponentInfo
	Lifecycle        string
	compositions     []GetComposition
	Vuln             []GetVulnerabilities
	rawContent       []byte // Store raw content for manual parsing
	File             []GetComponent
}

func newSPDX3Doc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion, _ Signature) (Document, error) {
	log := logger.FromContext(ctx)
	var err error

	// Read raw content first for validation
	rawContent, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Reset reader for parsing
	reader := bytes.NewReader(rawContent)

	r := parse.NewReader()
	doc, err := r.FromReader(reader)
	if err != nil {
		return nil, err
	}

	spdx3Doc := &Spdx3Doc{
		doc:        doc,
		format:     format,
		ctx:        ctx,
		version:    version,
		rawContent: rawContent,
	}

	spdx3Doc.parse()
	for _, l := range spdx3Doc.Logs() {
		log.Debug(l)
	}

	return spdx3Doc, err
}

func (s Spdx3Doc) PrimaryComp() GetPrimaryComponentInfo {
	return &s.PrimaryComponent
}

func (s Spdx3Doc) Spec() Spec {
	return *s.SpdxSpec
}

func (s Spdx3Doc) Components() []GetComponent {
	return s.Comps
}

func (s Spdx3Doc) Files() []GetComponent {
	return s.File
}

func (s Spdx3Doc) Authors() []GetAuthor {
	return s.Auths
}

func (s Spdx3Doc) Tools() []GetTool {
	return s.SpdxTools
}

func (s Spdx3Doc) GetRelationships() []GetRelationship {
	return s.Relationships
}

func (s Spdx3Doc) GetOutgoingRelations(compID string) []GetRelationship {
	out := make([]GetRelationship, 0)
	for _, r := range s.Relationships {
		if r.GetFrom() == compID {
			out = append(out, r)
		}
	}
	return out
}

func (s Spdx3Doc) GetDirectDependencies(compID string, relTypes ...string) []GetComponent {
	deps := make([]GetComponent, 0)

	// 1. Get outgoing edges
	allKindOfRelationships := s.GetOutgoingRelations(compID)
	if len(allKindOfRelationships) == 0 {
		return deps
	}

	// 2. Build component lookup
	mapCompID := make(map[string]GetComponent)
	for _, c := range s.Components() {
		mapCompID[c.GetID()] = c
	}

	// 3. Resolve dependencies
	for _, r := range allKindOfRelationships {
		if !relTypeAllowed(r.GetType(), relTypes) {
			continue
		}

		if dep, ok := mapCompID[r.GetTo()]; ok {
			deps = append(deps, dep)
		}
	}

	return deps
}

func (s Spdx3Doc) Logs() []string {
	return s.logs
}

func (s Spdx3Doc) Lifecycles() []string {
	return []string{s.Lifecycle}
}

func (s Spdx3Doc) Manufacturer() GetManufacturer {
	return nil
}

func (s Spdx3Doc) Supplier() GetSupplier {
	return nil
}

func (s Spdx3Doc) Composition() []GetComposition {
	return s.compositions
}

func (s Spdx3Doc) Vulnerabilities() []GetVulnerabilities {
	return s.Vuln
}

func (s Spdx3Doc) Signature() GetSignature {
	return nil
}

func (s Spdx3Doc) SchemaValidation() bool {
	return s.spdxValidSchema
}

func (s *Spdx3Doc) parse() {
	s.parseDoc()
	s.parseSpec()
	s.parseSchemaValidation()
	s.parseAuthors()
	s.parseTool()
	s.parsePrimaryComponent()
	s.parseRelationships()
	s.parseComps()
	s.parseFiles()
}

func (s *Spdx3Doc) addToLogs(log string) {
	s.logs = append(s.logs, log)
}

func (s *Spdx3Doc) parseDoc() {
	if s.doc == nil {
		s.addToLogs("spdx3 doc is not parsable")
		return
	}

	// Lifecycle info can be derived from CreationInfo comment or profiles
	// Upstream doesn't have HasLifecycle/GetLifecycleInfo methods
	if s.doc.CreationInfo != nil && s.doc.CreationInfo.Comment != "" {
		s.Lifecycle = s.doc.CreationInfo.Comment
	}
}

func (s *Spdx3Doc) parseSpec() {
	sp := NewSpec()

	sp.Format = string(s.format)
	sp.SpecType = string(SBOMSpecSPDX)

	// Default version
	sp.Version = "3.0"

	// Get name and spdxID from the document
	sp.Name = s.doc.GetName()
	sp.Spdxid = s.doc.GetSpdxID()

	if s.doc.CreationInfo != nil {
		version := s.doc.CreationInfo.SpecVersion
		if strings.HasPrefix(version, "SPDX-") {
			sp.Version = strings.TrimPrefix(version, "SPDX-")
		} else if version != "" {
			sp.Version = version
		}

		ci := s.doc.CreationInfo

		// Creation timestamp - format time.Time to RFC3339 string
		if !ci.Created.IsZero() {
			sp.CreationTimestamp = ci.Created.Format(time.RFC3339)
		}

		sp.Comment = ci.Comment

		// Organization - find in CreatedBy by looking up the actual Organization/Person
		// In SPDX 3.0, CreatedBy contains Agent references (SpdxID only), need to lookup actual entity
		for _, creator := range ci.CreatedBy {
			if creator.SpdxID == "" {
				continue
			}
			// Look up the Organization or Person by SpdxID
			orgName := ""
			for _, org := range s.doc.Organizations {
				if org.SpdxID == creator.SpdxID {
					orgName = org.Name
					break
				}
			}
			if orgName == "" {
				// Try looking up in Persons
				for _, person := range s.doc.Persons {
					if person.SpdxID == creator.SpdxID {
						orgName = person.Name
						break
					}
				}
			}
			if orgName != "" {
				sp.Organization = orgName
				break
			}
		}
	}

	// Namespace - from SpdxDocument namespaceMap (SPDX 3.0 uses namespaceMap array)
	if s.doc.SpdxDocument != nil && len(s.doc.SpdxDocument.NamespaceMap) > 0 {
		// Use the first namespace entry
		ns := s.doc.SpdxDocument.NamespaceMap[0].Namespace
		sp.Namespace = ns
		sp.URI = ns
	}

	// Data license - SPDX 3.0 stores it as a reference in SpdxID
	dataLicense := s.doc.GetDataLicense()
	if dataLicense != nil {
		licenseID := dataLicense.SpdxID
		if licenseID == "" {
			licenseID = dataLicense.Name
		}
		if licenseID != "" {
			lics := licenses.LookupExpression(licenseID, nil)
			sp.Licenses = append(sp.Licenses, lics...)
		}
	}

	sp.isReqFieldsPresent = true

	s.SpdxSpec = sp
}

func (s *Spdx3Doc) parseSchemaValidation() {
	s.spdxValidSchema = false
	s.addToLogs("processing parseSchemaValidation for spdx3.0 SBOM")

	if s.format != FileFormatJSON {
		s.addToLogs("schema validation skipped: non-JSON SBOM")
		return
	}

	version := normalizeSpdxVersion(s.Spec().GetVersion())
	s.addToLogs(fmt.Sprintf("spec: %s, version: %s", s.Spec().GetSpecType(), version))

	result := validation.Validate("spdx", version, s.rawContent)

	s.addToLogs(fmt.Sprintf("schema valid: %v", result.Valid))
	s.spdxValidSchema = result.Valid

	for _, l := range result.Logs {
		s.addToLogs(l)
	}
}

func (s *Spdx3Doc) parseAuthors() {
	s.Auths = []GetAuthor{}

	// In SPDX 3.0, authors are Organizations and Persons referenced in CreationInfo.CreatedBy
	// CreatedBy contains Agent references (via SpdxID) to the actual author entities
	if s.doc.CreationInfo == nil {
		return
	}

	// Build a set of SpdxIDs from CreatedBy
	createdByIDs := make(map[string]bool)
	for _, agent := range s.doc.CreationInfo.CreatedBy {
		if agent.SpdxID != "" {
			createdByIDs[agent.SpdxID] = true
		}
	}

	// Only add Organizations that are in CreatedBy
	for _, org := range s.doc.Organizations {
		if !createdByIDs[org.SpdxID] {
			continue
		}
		email := ""
		// Extract email from externalIdentifier
		for _, extId := range org.ExternalIdentifier {
			if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
				email = extId.Identifier
				break
			}
		}
		// Skip only if both name and email are empty
		if org.Name == "" && email == "" {
			continue
		}
		a := Author{
			Name:       org.Name,
			Email:      email,
			AuthorType: "organization",
		}
		s.Auths = append(s.Auths, a)
	}

	// Only add Persons that are in CreatedBy
	for _, person := range s.doc.Persons {
		if !createdByIDs[person.SpdxID] {
			continue
		}
		email := ""
		// Extract email from externalIdentifier
		for _, extId := range person.ExternalIdentifier {
			if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
				email = extId.Identifier
				break
			}
		}
		// Skip only if both name and email are empty
		if person.Name == "" && email == "" {
			continue
		}
		a := Author{
			Name:       person.Name,
			Email:      email,
			AuthorType: "person",
		}
		s.Auths = append(s.Auths, a)
	}
}

func (s *Spdx3Doc) parseTool() {
	s.SpdxTools = []GetTool{}

	if s.doc.CreationInfo == nil {
		return
	}

	extractVersion := func(inputName string) (string, string) {
		parts := strings.Split(inputName, "-")

		// if there are no "-" its a bad string
		if len(parts) == 1 {
			return inputName, ""
		}

		// The last element after splitting is the version
		version := parts[len(parts)-1]

		name := strings.Join(parts[:len(parts)-1], "-")

		// check if version has atleast one-digit
		// if not, then it is not a version
		for _, r := range version {
			if unicode.IsDigit(r) {
				return name, version
			}
		}

		return inputName, ""
	}

	// Build a set of SpdxIDs from CreatedUsing (document-level tools only)
	createdUsingIDs := make(map[string]bool)
	for _, tool := range s.doc.CreationInfo.CreatedUsing {
		if tool.SpdxID != "" {
			createdUsingIDs[tool.SpdxID] = true
		}
	}

	// Only add Tools that are referenced in CreatedUsing
	for _, tool := range s.doc.Tools {
		if !createdUsingIDs[tool.SpdxID] {
			continue
		}
		t := Tool{}
		t.Name, t.Version = extractVersion(tool.Name)
		s.SpdxTools = append(s.SpdxTools, t)
	}
}

func (s *Spdx3Doc) parsePrimaryComponent() {
	// Find primary package via DESCRIBES relationships
	var primaryPkg **spdx.Package
	for _, rel := range s.doc.Relationships {
		if rel.RelationshipType == spdx.RelationshipTypeDescribes {
			for _, to := range rel.To {
				toID := to.GetSpdxID()
				if pkg := s.doc.GetPackageByID(toID); pkg != nil {
					primaryPkg = &pkg
					break
				}
			}
		}
		if primaryPkg != nil {
			break
		}
	}

	if primaryPkg == nil {
		return
	}

	pkg := *primaryPkg
	s.PrimaryComponent.Present = true
	s.PrimaryComponent.ID = strings.TrimPrefix(pkg.SpdxID, "SPDXRef-")
	s.PrimaryComponent.Name = pkg.Name
	s.PrimaryComponent.Version = pkg.PackageVersion
	s.PrimaryComponent.Type = string(pkg.PrimaryPurpose)
}

// convertRelType converts SPDX 3.0 camelCase relationship type to UPPER_CASE
// e.g., "dependsOn" -> "DEPENDS_ON", "contains" -> "CONTAINS"
func convertRelType(rt spdx.RelationshipType) string {
	s := string(rt)
	var result []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToUpper(string(result))
}

func (s *Spdx3Doc) parseRelationships() {
	s.Relationships = make([]GetRelationship, 0)

	for _, rel := range s.doc.Relationships {
		// Skip "describes" relationships (document -> primary component)
		if rel.RelationshipType == spdx.RelationshipTypeDescribes {
			continue
		}

		// Only include component-to-component dependency relationships
		// Skip license, vulnerability assessment, and other non-dependency relationships
		if !isComponentDependencyRelationship(rel.RelationshipType) {
			continue
		}

		// SPDX 3.0 relationships can have multiple targets
		// Flatten them into individual From->To relationships
		for _, to := range rel.To {
			r := Relationship{
				From: strings.TrimPrefix(rel.From.GetSpdxID(), "SPDXRef-"),
				To:   strings.TrimPrefix(to.GetSpdxID(), "SPDXRef-"),
				Type: convertRelType(rel.RelationshipType),
			}
			s.Relationships = append(s.Relationships, r)
		}
	}
}

// isComponentDependencyRelationship returns true if the relationship type
// represents an actual component-to-component dependency (not licenses,
// vulnerability assessments, or other attribute relationships).
func isComponentDependencyRelationship(relType spdx.RelationshipType) bool {
	switch relType {
	// Core dependency types
	case spdx.RelationshipTypeDependsOn:
		return true

	case spdx.RelationshipTypeContains:
		return true

	// Linking relationships
	case spdx.RelationshipTypeHasDynamicLink,
		spdx.RelationshipTypeHasStaticLink:
		return true

	// Optional/provided dependencies
	case spdx.RelationshipTypeHasOptionalDependency,
		spdx.RelationshipTypeHasProvidedDependency:
		return true

	// Prerequisite/requirement dependencies
	case spdx.RelationshipTypeHasPrerequisite,
		spdx.RelationshipTypeHasRequirement:
		return true

	// Manifest/dependency tracking
	case spdx.RelationshipTypeHasDependencyManifest:
		return true

	// Build relationships (input/output/tool/host)
	case spdx.RelationshipTypeHasInput,
		spdx.RelationshipTypeHasOutput,
		spdx.RelationshipTypeHasHost,
		spdx.RelationshipTypeUsesTool:
		return true

	// Generation
	case spdx.RelationshipTypeGenerates:
		return true

	// Configuration
	case spdx.RelationshipTypeConfigures:
		return true

	// NOT dependencies - license relationships
	case spdx.RelationshipTypeHasDeclaredLicense,
		spdx.RelationshipTypeHasConcludedLicense:
		return false

	// NOT dependencies - vulnerability assessment relationships
	case spdx.RelationshipTypeHasAssessmentFor,
		spdx.RelationshipTypeHasAssociatedVulnerability,
		spdx.RelationshipTypeAffects,
		spdx.RelationshipTypeDoesNotAffect,
		spdx.RelationshipTypeFixedIn,
		spdx.RelationshipTypeUnderInvestigationFor,
		spdx.RelationshipTypeFoundBy,
		spdx.RelationshipTypeReportedBy,
		spdx.RelationshipTypeFixedBy,
		spdx.RelationshipTypePublishedBy,
		spdx.RelationshipTypeRepublishedBy,
		spdx.RelationshipTypeExploitCreatedBy,
		spdx.RelationshipTypeCoordinatedBy:
		return false

	// NOT dependencies - file/metadata relationships
	case spdx.RelationshipTypeHasDataFile,
		spdx.RelationshipTypeHasDocumentation,
		spdx.RelationshipTypeHasTest,
		spdx.RelationshipTypeHasTestCase,
		spdx.RelationshipTypeHasExample,
		spdx.RelationshipTypeHasEvidence,
		spdx.RelationshipTypeHasMetadata,
		spdx.RelationshipTypeHasAddedFile,
		spdx.RelationshipTypeHasDeletedFile,
		spdx.RelationshipTypeHasDistributionArtifact:
		return false

	// NOT dependencies - variant/specification relationships
	case spdx.RelationshipTypeHasVariant,
		spdx.RelationshipTypeHasSpecification,
		spdx.RelationshipTypeHasOptionalComponent:
		return false

	// NOT dependencies - archive/packaging relationships
	case spdx.RelationshipTypeExpandsTo,
		spdx.RelationshipTypePackagedBy,
		spdx.RelationshipTypePatchedBy,
		spdx.RelationshipTypeModifiedBy,
		spdx.RelationshipTypeCopiedTo,
		spdx.RelationshipTypeAmendedBy:
		return false

	// NOT dependencies - serialization
	case spdx.RelationshipTypeSerializedInArtifact:
		return false

	// NOT dependencies - dataset relationships
	case spdx.RelationshipTypeTrainedOn,
		spdx.RelationshipTypeTestedOn:
		return false

	// NOT dependencies - ancestry
	case spdx.RelationshipTypeAncestorOf,
		spdx.RelationshipTypeDescendantOf:
		return false

	// NOT dependencies - delegation/invocation
	case spdx.RelationshipTypeDelegatedTo,
		spdx.RelationshipTypeInvokedBy:
		return false

	// NOT dependencies - availability
	case spdx.RelationshipTypeAvailableFrom:
		return false

	// NOT dependencies - other/catch-all
	case spdx.RelationshipTypeOther:
		return false

	default:
		// For unknown relationship types, be conservative and don't treat as dependency
		return false
	}
}

func (s *Spdx3Doc) parseComps() {
	s.Comps = []GetComponent{}

	for _, pkg := range s.doc.Packages {
		nc := NewComponent()

		nc.Version = pkg.PackageVersion
		nc.Name = pkg.Name
		nc.Purpose = string(pkg.PrimaryPurpose)
		nc.Spdxid = pkg.SpdxID
		nc.CopyRight = pkg.CopyrightText
		nc.FileAnalyzed = true // SPDX 3.0 doesn't have explicit FilesAnalyzed, assume true
		nc.isReqFieldsPresent = s.pkgRequiredFields(pkg)
		nc.Purls = s.purls(pkg)
		nc.Cpes = s.cpes(pkg)
		nc.OmniID = nil
		nc.Swhid = nil
		nc.Swid = nil
		nc.Checksums = s.checksums(pkg)
		nc.ExternalRefs = s.externalRefs(pkg)
		nc.Licenses = s.licenses(pkg)
		nc.DeclaredLicense = s.declaredLicenses(pkg)
		nc.ConcludedLicense = s.concludedLicenses(pkg)
		nc.ID = strings.TrimPrefix(pkg.SpdxID, "SPDXRef-")

		// Source code URL and download location from SPDX 3.0 Package fields
		// Use SourceInfo for source code URL, fallback to HomePage if empty
		if pkg.SourceInfo != "" {
			nc.SourceCodeURL = pkg.SourceInfo
		} else {
			nc.SourceCodeURL = pkg.HomePage
		}

		nc.DownloadLocation = pkg.DownloadLocation

		// Supplier (SuppliedBy in SPDX 3.0)
		nc.Supplier = s.extractSupplier(pkg.SuppliedBy)
		nc.Manufacture = s.extractManufacturer(pkg.OriginatedBy)

		// If no supplier but has manufacturer, copy manufacturer to supplier
		if pkg.SuppliedBy == nil && len(pkg.OriginatedBy) > 0 {
			nc.Supplier = Supplier{
				Name:  nc.Manufacture.Name,
				Email: nc.Manufacture.Email,
				URL:   nc.Manufacture.URL,
			}
		}

		s.Comps = append(s.Comps, nc)

	}
}

// Helper methods for parseComps

// isNoAssertion checks if a value is NOASSERTION (case-insensitive)
func isNoAssertion(val string) bool {
	return strings.EqualFold(val, "NOASSERTION")
}

// extractSupplier extracts supplier information from an SPDX 3.0 Agent reference
// Looks up the actual Person or Organization and extracts name, email, and URL
func (s *Spdx3Doc) extractSupplier(suppliedBy *spdx.Agent) Supplier {
	if suppliedBy == nil {
		return Supplier{}
	}

	supplierName := ""
	supplierEmail := ""
	supplierURL := ""

	// Try to look up by SpdxID match first (for reference case)
	if suppliedBy.SpdxID != "" {
		// First check Organizations
		for _, org := range s.doc.Organizations {
			if org.SpdxID == suppliedBy.SpdxID {
				supplierName = org.Name
				// Extract email and URL from externalIdentifier
				for _, extId := range org.ExternalIdentifier {
					if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
						supplierEmail = extId.Identifier
					}
					if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeUrlScheme {
						supplierURL = extId.Identifier
					}
				}
				break
			}
		}
		// If not found in Organizations, check Persons
		if supplierName == "" && supplierEmail == "" {
			for _, person := range s.doc.Persons {
				if person.SpdxID == suppliedBy.SpdxID {
					supplierName = person.Name
					// Extract email and URL from externalIdentifier
					for _, extId := range person.ExternalIdentifier {
						if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
							supplierEmail = extId.Identifier
						}
						if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeUrlScheme {
							supplierURL = extId.Identifier
						}
					}
					break
				}
			}
		}
	}

	// Fall back to Name if already populated (embedded case) or lookup failed
	if supplierName == "" {
		supplierName = suppliedBy.Name
	}

	return Supplier{
		Name:  supplierName,
		Email: supplierEmail,
		URL:   supplierURL,
	}
}

// extractManufacturer extracts manufacturer information from SPDX 3.0 OriginatedBy agents
// Looks up the actual Person or Organization and extracts name, email, and URL
func (s *Spdx3Doc) extractManufacturer(originatedBy []spdx.Agent) Manufacturer {
	if len(originatedBy) == 0 {
		return Manufacturer{}
	}

	orig := originatedBy[0]
	manufacturerName := ""
	manufacturerEmail := ""
	manufacturerURL := ""

	// Try to look up by SpdxID match first (for reference case)
	if orig.SpdxID != "" {
		// First check Organizations
		for _, org := range s.doc.Organizations {
			if org.SpdxID == orig.SpdxID {
				manufacturerName = org.Name
				// Extract email and URL from externalIdentifier
				for _, extId := range org.ExternalIdentifier {
					if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
						manufacturerEmail = extId.Identifier
					}
					if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeUrlScheme {
						manufacturerURL = extId.Identifier
					}
				}
				break
			}
		}
		// If not found in Organizations, check Persons
		if manufacturerName == "" && manufacturerEmail == "" {
			for _, person := range s.doc.Persons {
				if person.SpdxID == orig.SpdxID {
					manufacturerName = person.Name
					// Extract email and URL from externalIdentifier
					for _, extId := range person.ExternalIdentifier {
						if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeEmail {
							manufacturerEmail = extId.Identifier
						}
						if extId.ExternalIdentifierType == spdx.ExternalIdentifierTypeUrlScheme {
							manufacturerURL = extId.Identifier
						}
					}
					break
				}
			}
		}
	}

	// Fall back to Name if already populated (embedded case) or lookup failed
	if manufacturerName == "" {
		manufacturerName = orig.Name
	}

	return Manufacturer{
		Name:  manufacturerName,
		Email: manufacturerEmail,
		URL:   manufacturerURL,
	}
}

func (s *Spdx3Doc) pkgRequiredFields(pkg *spdx.Package) bool {
	// Check required fields for NTIA minimum elements
	if pkg.Name == "" {
		return false
	}
	if pkg.SuppliedBy == nil || isNoAssertion(pkg.SuppliedBy.Name) {
		return false
	}
	return true
}

func (s *Spdx3Doc) purls(pkg *spdx.Package) []purl.PURL {
	urls := make([]purl.PURL, 0)
	// PURL is stored as ExternalIdentifier in SPDX 3.0
	for _, ei := range pkg.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypePackageUrl {
			prl := purl.NewPURL(ei.Identifier)
			if prl.Valid() {
				urls = append(urls, prl)
			}
		}
	}
	return urls
}

func (s *Spdx3Doc) cpes(pkg *spdx.Package) []cpe.CPE {
	urls := make([]cpe.CPE, 0)
	// CPE is stored as ExternalIdentifier in SPDX 3.0
	for _, ei := range pkg.ExternalIdentifier {
		if ei.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe22 ||
			ei.ExternalIdentifierType == spdx.ExternalIdentifierTypeCpe23 {
			cpeV := cpe.NewCPE(ei.Identifier)
			if cpeV.Valid() {
				urls = append(urls, cpeV)
			}
		}
	}
	return urls
}

func (s *Spdx3Doc) checksums(pkg *spdx.Package) []GetChecksum {
	chks := make([]GetChecksum, 0)

	if len(pkg.VerifiedUsing) > 0 {
		for _, vu := range pkg.VerifiedUsing {
			if h, ok := interface{}(vu).(spdx.Hash); ok {
				ck := Checksum{
					Alg:     string(h.Algorithm),
					Content: h.HashValue,
				}
				chks = append(chks, ck)
			}
		}
	}
	return chks
}

func (s *Spdx3Doc) externalRefs(pkg *spdx.Package) []GetExternalReference {
	extRefs := make([]GetExternalReference, 0, len(pkg.ExternalRef))
	for _, ext := range pkg.ExternalRef {
		// Join locator strings if multiple
		locator := ""
		if len(ext.Locator) > 0 {
			locator = ext.Locator[0]
		}
		extRef := ExternalReference{
			RefType:    string(ext.ExternalRefType),
			RefLocator: locator,
		}
		extRefs = append(extRefs, extRef)
	}
	return extRefs
}

func (s *Spdx3Doc) licenses(pkg *spdx.Package) []licenses.License {
	lics := []licenses.License{}
	// Use GetLicensesFor to get license info via relationships
	if s.doc != nil {
		licenseInfo := s.doc.GetLicensesFor(pkg.SpdxID)
		for _, concluded := range licenseInfo.ConcludedLicenses {
			if concluded.Name != "" {
				lics = append(lics, licenses.LookupExpression(concluded.Name, nil)...)
			}
		}
	}
	return lics
}

func (s *Spdx3Doc) declaredLicenses(pkg *spdx.Package) []licenses.License {
	lics := []licenses.License{}

	// Use GetLicensesFor to get declared license info via relationships
	if s.doc != nil {
		licenseInfo := s.doc.GetLicensesFor(pkg.SpdxID)
		for _, declared := range licenseInfo.DeclaredLicenses {
			if declared.Name != "" {
				lics = append(lics, licenses.LookupExpression(declared.Name, nil)...)
			}
		}
	}

	return lics
}

func (s *Spdx3Doc) concludedLicenses(pkg *spdx.Package) []licenses.License {
	lics := []licenses.License{}

	// Use GetLicensesFor to get concluded license info via relationships
	if s.doc != nil {
		licenseInfo := s.doc.GetLicensesFor(pkg.SpdxID)
		for _, concluded := range licenseInfo.ConcludedLicenses {
			if concluded.Name != "" {
				lics = append(lics, licenses.LookupExpression(concluded.Name, nil)...)
			}
		}
	}

	return lics
}

func (s *Spdx3Doc) parseFiles() {
	s.File = []GetComponent{}

	for _, f := range s.doc.Files {
		nc := NewComponent()

		nc.Name = f.Name
		nc.Spdxid = f.SpdxID
		nc.ID = f.SpdxID
		nc.PackageFilename = f.Name

		// File checksums/hashes - VerifiedUsing in SPDX 3.0
		if len(f.VerifiedUsing) > 0 {
			chks := make([]GetChecksum, 0, len(f.VerifiedUsing))
			for _, vu := range f.VerifiedUsing {
				// Type assertion needed since VerifiedUsing is []IntegrityMethod
				if h, ok := interface{}(vu).(spdx.Hash); ok {
					ck := Checksum{
						Alg:     string(h.Algorithm),
						Content: h.HashValue,
					}
					chks = append(chks, ck)
				}
			}
			if len(chks) > 0 {
				nc.Checksums = chks
			}
		}

		// File purpose (SPDX 3.0: PrimaryPurpose, AdditionalPurpose)
		nc.Purpose = string(f.PrimaryPurpose)

		// File comment
		nc.CopyRight = f.Comment

		// External references (if any) - ExternalRef in SPDX 3.0
		if len(f.ExternalRef) > 0 {
			extRefs := make([]GetExternalReference, 0, len(f.ExternalRef))
			for _, ext := range f.ExternalRef {
				// Join locator strings if multiple
				locator := ""
				if len(ext.Locator) > 0 {
					locator = ext.Locator[0]
				}
				extRef := ExternalReference{
					RefType:    string(ext.ExternalRefType),
					RefLocator: locator,
				}
				extRefs = append(extRefs, extRef)
			}
			nc.ExternalRefs = extRefs
		}

		s.File = append(s.File, nc)
	}
}
