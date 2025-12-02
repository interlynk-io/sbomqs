// Copyright 2025 Interlynk.io
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
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/spdx-zen/parse"
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
		spdxValidSchema: true,
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
	// Check if the document itself has a supplier (from the root/primary package)
	if s.doc == nil {
		return nil
	}
	
	// First, check if we have a primary component with supplier
	if s.PrimaryComponent.ID != "" {
		for _, pkg := range s.doc.Packages() {
			if pkg.SpdxID == s.PrimaryComponent.ID && pkg.Supplier != nil {
				return &Supplier{
					Name:  pkg.Supplier.Name,
					Email: "", // SPDX 3.0 doesn't have email in AgentInfo
				}
			}
		}
	}
	
	// If no primary component supplier, check if the document has a supplier
	// This would be stored as the supplier of the SBOM itself (if it exists)
	// For now, return nil as document-level supplier is not directly available
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
	// SPDX 3.0 maps lifecycle to Software/Sbom/sbomType
	// Check creation info comment for lifecycle information
	if creationInfo := s.doc.CreationInfo(); creationInfo != nil && creationInfo.Comment != "" {
		comment := strings.ToLower(creationInfo.Comment)
		// Look for lifecycle phase keywords
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
	
	// SPDX 3.0 data license
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

		// Handle supplier
		if supplier := pkg.Supplier; supplier != nil {
			nc.Supplier = Supplier{
				Name:  supplier.Name,
				Email: "", // SPDX 3.0 doesn't have email in AgentInfo
			}
		}

		// Handle originator/manufacturer
		if originators := pkg.Originator; len(originators) > 0 {
			nc.manufacturer = Manufacturer{
				Name:  originators[0].Name,
				Email: "",
			}
			// Also set as author
			for _, orig := range originators {
				nc.Athrs = append(nc.Athrs, Author{
					Name:       orig.Name,
					Email:      "",
					AuthorType: strings.ToLower(orig.Type),
				})
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
		if strings.ToLower(creator.Type) != "tool" && strings.ToLower(creator.Type) != "softwareagent" {
			a := Author{
				Name:       creator.Name,
				Email:      "", // SPDX 3.0 doesn't have email in AgentInfo
				AuthorType: strings.ToLower(creator.Type),
			}
			s.Auths = append(s.Auths, a)
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
	
	// Find primary component through DESCRIBES relationship
	for _, rel := range relationships {
		relType := strings.ToLower(rel.RelationshipType)
		if relType == "describes" {
			// In SPDX 3.0, the document describes the primary component
			for _, to := range rel.To {
				s.PrimaryComponent.ID = to
				s.PrimaryComponent.Present = true
				
				// Find the package details
				for _, pkg := range s.doc.Packages() {
					if pkg.SpdxID == to {
						s.PrimaryComponent.Name = pkg.Name
						s.PrimaryComponent.Version = pkg.Version
						break
					}
				}
				break // Use first described element as primary
			}
		}
	}

	// Build dependency map
	for _, rel := range relationships {
		relType := strings.ToLower(rel.RelationshipType)
		// Handle both SPDX 2.x style (CONTAINS, DEPENDS_ON) and SPDX 3.0 style (contains, dependsOn)
		if relType == "contains" || relType == "depends_on" || relType == "dependson" {
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

	// In SPDX 3.0, tools can be in CreatedBy or CreatedUsing
	for _, creator := range creationInfo.CreatedBy {
		if strings.ToLower(creator.Type) == "tool" || strings.ToLower(creator.Type) == "softwareagent" {
			t := Tool{
				Name:    creator.Name,
				Version: "", // Version might be embedded in the name
			}
			// Try to extract version from name (e.g., "tool-1.2.3")
			t.Name, t.Version = extractToolVersion(creator.Name)
			s.SpdxTools = append(s.SpdxTools, t)
		}
	}
	
	for _, tool := range creationInfo.CreatedUsing {
		t := Tool{
			Name:    tool.Name,
			Version: "",
		}
		t.Name, t.Version = extractToolVersion(tool.Name)
		s.SpdxTools = append(s.SpdxTools, t)
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
	
	// SPDX 3.0 required fields
	if s.doc.SpdxID() == "" {
		s.addToLogs("spdx3 doc is missing SPDXIdentifier")
		return false
	}
	
	if s.doc.Name() == "" {
		s.addToLogs("spdx3 doc is missing Name")
		return false
	}
	
	creationInfo := s.doc.CreationInfo()
	if creationInfo == nil {
		s.addToLogs("spdx3 doc is missing creation info")
		return false
	}
	
	if len(creationInfo.CreatedBy) == 0 {
		s.addToLogs("spdx3 doc is missing creators")
		return false
	}
	
	if creationInfo.Created.IsZero() {
		s.addToLogs("spdx3 doc is missing created timestamp")
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
	seenPurls := make(map[string]bool)
	
	// Check PackageURL field (primary source for SPDX 3.0)
	if pkg.PackageURL != "" {
		prl := purl.NewPURL(pkg.PackageURL)
		if prl.Valid() {
			purlStr := prl.String()
			if !seenPurls[purlStr] {
				urls = append(urls, prl)
				seenPurls[purlStr] = true
			}
		} else {
			s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s invalid purl found: %s", pkg.Name, pkg.PackageURL))
		}
	}
	
	// Check external IDs for PURLs
	for _, extID := range pkg.ExternalIDs {
		if strings.ToLower(extID.Type) == "purl" || strings.ToLower(extID.Type) == "packageurl" || strings.HasPrefix(extID.Identifier, "pkg:") {
			prl := purl.NewPURL(extID.Identifier)
			if prl.Valid() {
				purlStr := prl.String()
				if !seenPurls[purlStr] {
					urls = append(urls, prl)
					seenPurls[purlStr] = true
				}
			}
		}
	}
	
	// Also check external references for package manager type
	for _, extRef := range pkg.ExternalRefs {
		if strings.Contains(strings.ToLower(extRef.Type), "package") || strings.HasPrefix(extRef.Locator, "pkg:") {
			prl := purl.NewPURL(extRef.Locator)
			if prl.Valid() {
				purlStr := prl.String()
				if !seenPurls[purlStr] {
					urls = append(urls, prl)
					seenPurls[purlStr] = true
				}
			}
		}
	}
	
	if len(urls) == 0 {
		s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s no purls found", pkg.Name))
	}
	
	return urls
}

func (s *Spdx3Doc) cpes(pkg *parse.PackageInfo) []cpe.CPE {
	cpes := make([]cpe.CPE, 0)
	seenCpes := make(map[string]bool)
	
	// Check external IDs for CPEs
	for _, extID := range pkg.ExternalIDs {
		if strings.Contains(strings.ToLower(extID.Type), "cpe") || strings.HasPrefix(extID.Identifier, "cpe:") {
			cpeV := cpe.NewCPE(extID.Identifier)
			if cpeV.Valid() {
				cpeStr := cpeV.String()
				if !seenCpes[cpeStr] {
					cpes = append(cpes, cpeV)
					seenCpes[cpeStr] = true
				}
			} else {
				s.addToLogs(fmt.Sprintf("spdx3 doc pkg %s invalid cpe found: %s", pkg.Name, extID.Identifier))
			}
		}
	}
	
	// Also check external references for CPE type
	for _, extRef := range pkg.ExternalRefs {
		if strings.Contains(strings.ToLower(extRef.Type), "cpe") || strings.HasPrefix(extRef.Locator, "cpe:") {
			cpeV := cpe.NewCPE(extRef.Locator)
			if cpeV.Valid() {
				cpeStr := cpeV.String()
				if !seenCpes[cpeStr] {
					cpes = append(cpes, cpeV)
					seenCpes[cpeStr] = true
				}
			}
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

func (s *Spdx3Doc) licenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}
	
	// SPDX 3.0 uses relationships for licenses
	// First check if pkg.LicenseInfo is populated (for compatibility)
	if pkg.LicenseInfo != nil {
		// Prefer concluded license
		if pkg.LicenseInfo.Concluded != "" {
			conLics := licenses.LookupExpression(pkg.LicenseInfo.Concluded, nil)
			if len(conLics) > 0 {
				return conLics
			}
		}
		
		// Fall back to declared license
		if pkg.LicenseInfo.Declared != "" {
			decLics := licenses.LookupExpression(pkg.LicenseInfo.Declared, nil)
			if len(decLics) > 0 {
				return decLics
			}
		}
	}
	
	// If no LicenseInfo, check relationships (SPDX 3.0 way)
	// First try concluded licenses
	concludedRels := s.doc.ConcludedLicenseFor(pkg.SpdxID)
	for _, rel := range concludedRels {
		for _, to := range rel.To {
			// The 'to' field contains the license expression
			conLics := licenses.LookupExpression(to, nil)
			lics = append(lics, conLics...)
		}
	}
	if len(lics) > 0 {
		return lics
	}
	
	// Fall back to declared licenses
	declaredRels := s.doc.DeclaredLicenseFor(pkg.SpdxID)
	for _, rel := range declaredRels {
		for _, to := range rel.To {
			decLics := licenses.LookupExpression(to, nil)
			lics = append(lics, decLics...)
		}
	}
	
	return lics
}

func (s *Spdx3Doc) declaredLicenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}
	
	// First check if pkg.LicenseInfo is populated (for compatibility)
	if pkg.LicenseInfo != nil && pkg.LicenseInfo.Declared != "" {
		decLics := licenses.LookupExpression(pkg.LicenseInfo.Declared, nil)
		lics = append(lics, decLics...)
	}
	
	// Also check relationships (SPDX 3.0 way)
	if len(lics) == 0 {
		declaredRels := s.doc.DeclaredLicenseFor(pkg.SpdxID)
		for _, rel := range declaredRels {
			for _, to := range rel.To {
				decLics := licenses.LookupExpression(to, nil)
				lics = append(lics, decLics...)
			}
		}
	}
	
	return lics
}

func (s *Spdx3Doc) concludedLicenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}
	
	// First check if pkg.LicenseInfo is populated (for compatibility)
	if pkg.LicenseInfo != nil && pkg.LicenseInfo.Concluded != "" {
		conLics := licenses.LookupExpression(pkg.LicenseInfo.Concluded, nil)
		lics = append(lics, conLics...)
	}
	
	// Also check relationships (SPDX 3.0 way)
	if len(lics) == 0 {
		concludedRels := s.doc.ConcludedLicenseFor(pkg.SpdxID)
		for _, rel := range concludedRels {
			for _, to := range rel.To {
				conLics := licenses.LookupExpression(to, nil)
				lics = append(lics, conLics...)
			}
		}
	}
	
	return lics
}