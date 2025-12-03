package sbom

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/spdx_zen/parse"
)

var (
	spdx3FileFormats    = []string{"json"}
	spdx3SpecVersions   = []string{"3.0", "3.0.0", "3.0.1", "SPDX-3.0", "SPDX-3.0.0", "SPDX-3.0.1"}
	spdx3PrimaryPurpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "source", "archive", "file", "install", "other"}
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
	Rels             []GetRelation
	logs             []string
	PrimaryComponent PrimaryComp
	Lifecycle        string
	Dependencies     map[string][]string
	composition      map[string]string
	Vuln             []GetVulnerabilities
}

func newSPDX3Doc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion, _ Signature) (Document, error) {
	_ = logger.FromContext(ctx)

	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	// Parse the document using spdx-zen
	d, err := parse.FromReader(f)
	if err != nil {
		return nil, err
	}

	doc := &Spdx3Doc{
		doc:             d,
		format:          format,
		ctx:             ctx,
		version:         version,
		spdxValidSchema: true, // Will be validated in requiredFields()
		Dependencies:    make(map[string][]string),
		composition:     make(map[string]string),
	}

	doc.parse()

	return doc, nil
}

func (s Spdx3Doc) PrimaryComp() GetPrimaryComp {
	return &s.PrimaryComponent
}

func (s Spdx3Doc) Spec() Spec {
	return *s.SpdxSpec
}

func (s Spdx3Doc) Components() []GetComponent {
	return s.Comps
}

func (s Spdx3Doc) Authors() []GetAuthor {
	return s.Auths
}

func (s Spdx3Doc) Tools() []GetTool {
	return s.SpdxTools
}

func (s Spdx3Doc) Relations() []GetRelation {
	return s.Rels
}

func (s Spdx3Doc) Logs() []string {
	return s.logs
}

func (s Spdx3Doc) Lifecycles() []string {
	// SPDX 3.0 maps lifecycle to Software/Sbom/sbomType
	// This could be in creation info comment or in sbomType field
	if s.Lifecycle != "" {
		return []string{s.Lifecycle}
	}
	return nil
}

func (s Spdx3Doc) Manufacturer() GetManufacturer {
	return nil
}

func (s Spdx3Doc) Supplier() GetSupplier {
	// SPDX 3.0 maps supplier to Core/Classes/Artifact.suppliedBy
	if s.doc == nil {
		return nil
	}

	// Check packages for supplier information
	for _, pkg := range s.doc.Packages() {
		if pkg.Supplier != nil && pkg.Supplier.Name != "" {
			supplier := &Supplier{
				Name: pkg.Supplier.Name,
			}
			// Try to extract email from name if in format "Name <email>"
			if strings.Contains(pkg.Supplier.Name, "<") && strings.Contains(pkg.Supplier.Name, ">") {
				if idx := strings.Index(pkg.Supplier.Name, "<"); idx > 0 {
					if endIdx := strings.Index(pkg.Supplier.Name, ">"); endIdx > idx {
						supplier.Email = strings.TrimSpace(pkg.Supplier.Name[idx+1 : endIdx])
						supplier.Name = strings.TrimSpace(pkg.Supplier.Name[:idx])
					}
				}
			}
			return supplier
		}
	}

	return nil
}

func (s Spdx3Doc) GetRelationships(componentID string) []string {
	return s.Dependencies[componentID]
}

func (s Spdx3Doc) GetComposition(componentID string) string {
	return s.composition[componentID]
}

func (s Spdx3Doc) Vulnerabilities() []GetVulnerabilities {
	return s.Vuln
}

func (s Spdx3Doc) Signature() GetSignature {
	// SPDX 3.0 does not have a signature field like some other formats
	return nil
}

func (s Spdx3Doc) SchemaValidation() bool {
	return s.spdxValidSchema
}

func (s *Spdx3Doc) parse() {
	s.parseDoc()
	s.parseSpec()
	s.parseAuthors()
	s.parseTool()
	s.parsePrimaryCompAndRelationships()
	s.parseComps()
}

func (s *Spdx3Doc) parseDoc() {
	if s.doc == nil {
		s.addToLogs("spdx3 doc is not parsable")
		return
	}

	// Check for lifecycle information in creation info comment
	if creationInfo := s.doc.CreationInfo(); creationInfo != nil && creationInfo.Comment != "" {
		// Fallback to checking creation info comment
		comment := strings.ToLower(creationInfo.Comment)
		if strings.Contains(comment, "build") || strings.Contains(comment, "runtime") ||
			strings.Contains(comment, "design") || strings.Contains(comment, "source") ||
			strings.Contains(comment, "analyzed") || strings.Contains(comment, "deployed") {
			s.Lifecycle = creationInfo.Comment
		}
	}
}

func (s *Spdx3Doc) parseSpec() {
	sp := NewSpec()
	sp.Format = string(s.format)
	sp.Version = s.doc.SpecVersion()

	creationInfo := s.doc.CreationInfo()
	if creationInfo != nil {
		sp.CreationTimestamp = creationInfo.Created.Format("2006-01-02T15:04:05Z")
		sp.Comment = creationInfo.Comment

		// Extract organization from creators
		for _, creator := range creationInfo.CreatedBy {
			if creator.Type == "Organization" {
				sp.Organization = creator.Name
			}
		}
	}

	sp.Spdxid = s.doc.SpdxID()
	sp.SpecType = string(SBOMSpecSPDX3)
	sp.Name = s.doc.Name()

	// SPDX 3.0 has namespace map instead of a single namespace
	if namespaceMap := s.doc.NamespaceMap(); len(namespaceMap) > 0 {
		// Use the first namespace as the primary one
		for _, ns := range namespaceMap {
			sp.Namespace = ns
			sp.URI = ns
			break
		}
	}

	sp.isReqFieldsPresent = s.requiredFields()

	// SPDX 3.0 data license - use the direct data license field
	sp.Licenses = []licenses.License{}
	if dataLicense := s.doc.DataLicense(); dataLicense != "" {
		lics := licenses.LookupExpression(dataLicense, nil)
		sp.Licenses = append(sp.Licenses, lics...)
	}

	s.Vuln = nil
	s.SpdxSpec = sp
}

func (s *Spdx3Doc) parseComps() {
	s.Comps = []GetComponent{}

	for _, pkg := range s.doc.Packages() {
		nc := NewComponent()

		nc.Version = pkg.Version
		nc.Name = pkg.Name
		nc.Spdxid = pkg.SpdxID
		nc.CopyRight = pkg.CopyrightText
		nc.Purpose = pkg.PrimaryPurpose
		nc.isReqFieldsPresent = s.pkgRequiredFields(pkg)
		nc.Purls = s.purls(pkg)
		nc.Cpes = s.cpes(pkg)
		nc.Checksums = s.checksums(pkg)
		nc.ExternalRefs = s.externalRefs(pkg)
		nc.Licenses = s.licenses(pkg)
		nc.DeclaredLicense = s.declaredLicenses(pkg)
		nc.ConcludedLicense = s.concludedLicenses(pkg)
		nc.ID = nc.Spdxid

		// Set source code URL from external references
		for _, extRef := range pkg.ExternalRefs {
			if extRef.Type == "sourceArtifact" || extRef.Type == "vcs" {
				nc.SourceCodeURL = extRef.Locator
				break
			}
		}

		// Set PackageLicenseConcluded for compatibility with some scorers
		if len(nc.ConcludedLicense) > 0 {
			// Create a license expression from concluded licenses
			licExprs := []string{}
			for _, lic := range nc.ConcludedLicense {
				if lic.ShortID() != "" {
					licExprs = append(licExprs, lic.ShortID())
				}
			}
			if len(licExprs) > 0 {
				nc.PackageLicenseConcluded = strings.Join(licExprs, " AND ")
			}
		}
		nc.DownloadLocation = pkg.DownloadLocation

		// Add content identifier support for NTIA unique identifiers
		if pkg.ContentIdentifier != "" {
			// Add content identifier as an external reference
			nc.ExternalRefs = append(nc.ExternalRefs, ExternalReference{
				RefType:    "contentIdentifier",
				RefLocator: pkg.ContentIdentifier,
			})
		}

		if strings.Contains(s.PrimaryComponent.ID, nc.Spdxid) {
			nc.PrimaryCompt = s.PrimaryComponent
		}

		// Handle supplier - check if it's not NOASSERTION
		if supplier := pkg.Supplier; supplier != nil && supplier.Name != "" && !strings.Contains(strings.ToUpper(supplier.Name), "NOASSERTION") {
			nc.Supplier = Supplier{
				Name: supplier.Name,
			}
			// Try to extract email from name if in format "Name <email>"
			if strings.Contains(supplier.Name, "<") && strings.Contains(supplier.Name, ">") {
				if idx := strings.Index(supplier.Name, "<"); idx > 0 {
					if endIdx := strings.Index(supplier.Name, ">"); endIdx > idx {
						nc.Supplier.Email = strings.TrimSpace(supplier.Name[idx+1 : endIdx])
						nc.Supplier.Name = strings.TrimSpace(supplier.Name[:idx])
					}
				}
			}
		}

		// Handle originator/manufacturer
		if originators := pkg.Originator; len(originators) > 0 {
			// Find first valid originator for manufacturer
			for _, orig := range originators {
				if orig.Name != "" && !strings.Contains(strings.ToUpper(orig.Name), "NOASSERTION") {
					nc.manufacturer = Manufacturer{
						Name: orig.Name,
					}
					// Try to extract email from name if in format "Name <email>"
					if strings.Contains(orig.Name, "<") && strings.Contains(orig.Name, ">") {
						if idx := strings.Index(orig.Name, "<"); idx > 0 {
							if endIdx := strings.Index(orig.Name, ">"); endIdx > idx {
								nc.manufacturer.Email = strings.TrimSpace(orig.Name[idx+1 : endIdx])
								nc.manufacturer.Name = strings.TrimSpace(orig.Name[:idx])
							}
						}
					}
					break
				}
			}
			// Also set all valid originators as authors
			for _, orig := range originators {
				if orig.Name != "" && !strings.Contains(strings.ToUpper(orig.Name), "NOASSERTION") {
					author := Author{
						Name:       orig.Name,
						AuthorType: strings.ToLower(orig.Type),
					}
					// Try to extract email from name
					if strings.Contains(orig.Name, "<") && strings.Contains(orig.Name, ">") {
						if idx := strings.Index(orig.Name, "<"); idx > 0 {
							if endIdx := strings.Index(orig.Name, ">"); endIdx > idx {
								author.Email = strings.TrimSpace(orig.Name[idx+1 : endIdx])
								author.Name = strings.TrimSpace(orig.Name[:idx])
							}
						}
					}
					nc.Athrs = append(nc.Athrs, author)
				}
			}
		}

		nc.isPrimary = s.PrimaryComponent.ID == nc.Spdxid
		nc.HasRelationships, nc.Count, nc.Dep = s.getComponentDependencies(nc.Spdxid)

		s.Comps = append(s.Comps, nc)
	}
}

func (s *Spdx3Doc) parseAuthors() {
	s.Auths = []GetAuthor{}

	creationInfo := s.doc.CreationInfo()
	if creationInfo == nil {
		return
	}

	for _, creator := range creationInfo.CreatedBy {
		// Filter out tools and software agents
		if strings.ToLower(creator.Type) != "tool" && strings.ToLower(creator.Type) != "softwareagent" {
			// Check if it's not NOASSERTION
			if creator.Name != "" && !strings.Contains(strings.ToUpper(creator.Name), "NOASSERTION") {
				a := Author{
					Name:       creator.Name,
					AuthorType: strings.ToLower(creator.Type),
				}
				// Try to extract email from name if in format "Name <email>"
				if strings.Contains(creator.Name, "<") && strings.Contains(creator.Name, ">") {
					if idx := strings.Index(creator.Name, "<"); idx > 0 {
						if endIdx := strings.Index(creator.Name, ">"); endIdx > idx {
							a.Email = strings.TrimSpace(creator.Name[idx+1 : endIdx])
							a.Name = strings.TrimSpace(creator.Name[:idx])
						}
					}
				}
				s.Auths = append(s.Auths, a)
			}
		}
	}
}

func (s *Spdx3Doc) getComponentDependencies(componentID string) (bool, int, []string) {
	deps := s.Dependencies[componentID]
	return len(deps) > 0, len(deps), deps
}

func (s *Spdx3Doc) parsePrimaryCompAndRelationships() {
	s.Dependencies = make(map[string][]string)

	relationships := s.doc.Relationships()

	// Use spdx-zen helper to find primary component
	if primaryPkg := s.doc.PrimaryPackage(); primaryPkg != nil {
		s.PrimaryComponent.ID = primaryPkg.SpdxID
		s.PrimaryComponent.Present = true
		s.PrimaryComponent.Name = primaryPkg.Name
		s.PrimaryComponent.Version = primaryPkg.Version
	}

	// Build dependency map
	for _, rel := range relationships {
		// Check relationship types
		if rel.RelationshipType == "contains" ||
			rel.RelationshipType == "dependsOn" ||
			rel.RelationshipType == "depends_on" || rel.RelationshipType == "dependson" { // fallback for older formats
			from := rel.From
			for _, to := range rel.To {
				s.Dependencies[from] = append(s.Dependencies[from], to)
				if from == s.PrimaryComponent.ID {
					s.PrimaryComponent.HasDependency = true
					s.PrimaryComponent.AllDependencies = append(s.PrimaryComponent.AllDependencies, to)
				}
			}
		}
	}

	s.PrimaryComponent.Dependecies = len(s.PrimaryComponent.AllDependencies)

	// Convert relationships to GetRelation interface
	for _, rel := range relationships {
		// SPDX 3.0 has To as an array, but our interface expects a single string
		// We'll create separate relations for each To element
		for _, to := range rel.To {
			r := Relation{
				From: rel.From,
				To:   to,
			}
			s.Rels = append(s.Rels, r)
		}
	}
}

func (s *Spdx3Doc) parseTool() {
	s.SpdxTools = []GetTool{}

	creationInfo := s.doc.CreationInfo()
	if creationInfo == nil {
		return
	}

	// Parse tools from CreatedBy (tools) and CreatedUsing
	var allTools []parse.AgentInfo
	allTools = append(allTools, creationInfo.CreatedUsing...)

	// Add tools from CreatedBy
	for _, creator := range creationInfo.CreatedBy {
		if strings.ToLower(creator.Type) == "tool" || strings.ToLower(creator.Type) == "softwareagent" {
			allTools = append(allTools, creator)
		}
	}

	for _, tool := range allTools {
		if tool.Name != "" && !strings.Contains(strings.ToUpper(tool.Name), "NOASSERTION") { // Filter out NOASSERTION tools
			t := Tool{
				Name:    tool.Name,
				Version: "", // Version might be embedded in the name or URL
			}
			// Try to extract version from name (e.g., "tool-1.2.3")
			t.Name, t.Version = extractToolVersion(tool.Name)
			s.SpdxTools = append(s.SpdxTools, t)
		}
	}
}

func extractToolVersion(toolName string) (string, string) {
	// Try to extract version from tool name
	parts := strings.Split(toolName, "-")
	if len(parts) > 1 {
		// Check if last part looks like a version
		lastPart := parts[len(parts)-1]
		if strings.Contains(lastPart, ".") || containsDigit(lastPart) {
			name := strings.Join(parts[:len(parts)-1], "-")
			return name, lastPart
		}
	}
	return toolName, ""
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func (s *Spdx3Doc) addToLogs(log string) {
	s.logs = append(s.logs, log)
}

func (s *Spdx3Doc) requiredFields() bool {
	if s.doc == nil {
		s.addToLogs("spdx3 doc is not parsable")
		return false
	}

	// Check basic required fields
	if s.doc.Name() == "" {
		s.addToLogs("spdx3 doc missing name")
		return false
	}

	if s.doc.SpdxID() == "" {
		s.addToLogs("spdx3 doc missing spdx identifier")
		return false
	}

	if s.doc.SpecVersion() == "" {
		s.addToLogs("spdx3 doc missing spec version")
		return false
	}

	if s.doc.DataLicense() == "" {
		s.addToLogs("spdx3 doc missing data license")
		return false
	}

	creationInfo := s.doc.CreationInfo()
	if creationInfo == nil {
		s.addToLogs("spdx3 doc missing creation info")
		return false
	}

	if len(creationInfo.CreatedBy) == 0 {
		s.addToLogs("spdx3 doc missing creators")
		return false
	}

	return true
}

func (s *Spdx3Doc) pkgRequiredFields(pkg *parse.PackageInfo) bool {
	if pkg.Name == "" {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s missing name", pkg.SpdxID))
		return false
	}

	if pkg.SpdxID == "" {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s missing identifier", pkg.Name))
		return false
	}

	// Download location is required unless it's NOASSERTION or NONE
	if pkg.DownloadLocation == "" {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s missing downloadLocation", pkg.Name))
		return false
	}

	return true
}

func (s *Spdx3Doc) purls(pkg *parse.PackageInfo) []purl.PURL {
	urls := make([]purl.PURL, 0)

	// Use spdx-zen helper to get PURLs
	purlStrs := pkg.PURLs()
	for _, purlStr := range purlStrs {
		prl := purl.NewPURL(purlStr)
		if prl.Valid() {
			urls = append(urls, prl)
		} else {
			s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s invalid purl found: %s", pkg.Name, purlStr))
		}
	}

	if len(urls) == 0 {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s no purls found", pkg.Name))
	}

	return urls
}

func (s *Spdx3Doc) cpes(pkg *parse.PackageInfo) []cpe.CPE {
	cpes := make([]cpe.CPE, 0)

	// Use spdx-zen helper to get CPEs
	cpeStrs := pkg.CPEs()
	for _, cpeStr := range cpeStrs {
		cpeV := cpe.NewCPE(cpeStr)
		if cpeV.Valid() {
			cpes = append(cpes, cpeV)
		} else {
			s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s invalid cpe found: %s", pkg.Name, cpeStr))
		}
	}

	if len(cpes) == 0 {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s no cpes found", pkg.Name))
	}

	return cpes
}

func (s *Spdx3Doc) checksums(pkg *parse.PackageInfo) []GetChecksum {
	chks := make([]GetChecksum, 0, len(pkg.Hashes))

	for _, h := range pkg.Hashes {
		ck := Checksum{
			Alg:     h.Algorithm,
			Content: h.Value,
		}
		chks = append(chks, ck)
	}

	if len(chks) == 0 {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s no checksum found", pkg.Name))
	}

	return chks
}

func (s *Spdx3Doc) externalRefs(pkg *parse.PackageInfo) []GetExternalReference {
	extRefs := make([]GetExternalReference, 0, len(pkg.ExternalRefs))

	for _, ext := range pkg.ExternalRefs {
		extRef := ExternalReference{
			RefType:    ext.Type,
			RefLocator: ext.Locator,
		}
		extRefs = append(extRefs, extRef)
	}

	if len(extRefs) == 0 {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s no externalReferences found", pkg.Name))
	}

	return extRefs
}

// Helper function to convert license expressions to license objects
func (s *Spdx3Doc) licenseExpressionsToLicenses(expressions []string) []licenses.License {
	lics := []licenses.License{}
	for _, licenseExpr := range expressions {
		parsedLics := licenses.LookupExpression(licenseExpr, nil)
		lics = append(lics, parsedLics...)
	}
	return lics
}

func (s *Spdx3Doc) licenses(pkg *parse.PackageInfo) []licenses.License {
	// Try concluded licenses first
	concludedLics := s.concludedLicenses(pkg)
	if len(concludedLics) > 0 {
		return concludedLics
	}

	// Fall back to declared licenses
	return s.declaredLicenses(pkg)
}

func (s *Spdx3Doc) declaredLicenses(pkg *parse.PackageInfo) []licenses.License {
	licenseStrs := pkg.DeclaredLicenses(s.doc)
	return s.licenseExpressionsToLicenses(licenseStrs)
}

func (s *Spdx3Doc) concludedLicenses(pkg *parse.PackageInfo) []licenses.License {
	licenseStrs := pkg.ConcludedLicenses(s.doc)
	return s.licenseExpressionsToLicenses(licenseStrs)
}
