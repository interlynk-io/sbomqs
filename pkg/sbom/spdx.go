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
	"strings"
	"unicode"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom/internal/parser"
	"github.com/samber/lo"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	spdx_common "github.com/spdx/tools-golang/spdx/v2/common"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
)

var (
	spdxFileFormats    = []string{"json", "yaml", "rdf", "tag-value"}
	spdxSpecVersions   = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3", "SPDX-3.0", "SPDX-3.0.1"}
	spdxPrimaryPurpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "source", "archive", "file", "install", "other"}
)

// SpdxDoc represents an SPDX document with its parsed components
type SpdxDoc struct {
	doc              *spdx.Document
	format           FileFormat
	version          FormatVersion
	config           *parser.Config
	SpdxSpec         *Specs
	spdxValidSchema  bool
	Comps            []GetComponent
	Auths            []GetAuthor
	SpdxTools        []GetTool
	Rels             []GetRelation
	PrimaryComponent PrimaryComp
	Lifecycle        string
	Dependencies     map[string][]string
	composition      map[string]string
	Vuln             []GetVulnerabilities
}

// SPDXOption is a functional option for SPDX document creation
type SPDXOption parser.Option

func newSPDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion, _ Signature) (Document, error) {
	// Default options with context
	opts := []SPDXOption{parser.WithContext(ctx)}
	return newSPDXDocWithOptions(f, format, version, opts...)
}

// newSPDXDocWithOptions creates a new SPDX document with functional options
func newSPDXDocWithOptions(f io.ReadSeeker, format FileFormat, version FormatVersion, opts ...SPDXOption) (Document, error) {
	// Apply options
	config := parser.DefaultConfig()
	for _, opt := range opts {
		opt.Apply(config)
	}
	
	_ = logger.FromContext(config.Context)
	var err error

	// Check if this is SPDX 3.x - use new parser
	versionStr := string(version)
	if strings.HasPrefix(versionStr, "SPDX-3.") {
		return newSPDX3Doc(config.Context, f, format, version)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	var d *spdx.Document

	switch format {
	case FileFormatJSON:
		d, err = spdx_json.Read(f)
	case FileFormatTagValue:
		d, err = spdx_tv.Read(f)
	case FileFormatYAML:
		d, err = spdx_yaml.Read(f)
	case FileFormatRDF:
		d, err = spdx_rdf.Read(f)
	default:
		err = fmt.Errorf("unsupported spdx format %s", string(format))
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse SPDX document: %w", err)
	}

	doc := &SpdxDoc{
		doc:             d,
		format:          format,
		config:          config,
		version:         version,
		spdxValidSchema: !config.SkipValidation,
	}

	doc.parse()

	return doc, nil
}

func (s SpdxDoc) PrimaryComp() GetPrimaryComp {
	return &s.PrimaryComponent
}

func (s SpdxDoc) Spec() Spec {
	return *s.SpdxSpec
}

func (s SpdxDoc) Components() []GetComponent {
	return s.Comps
}

func (s SpdxDoc) Authors() []GetAuthor {
	return s.Auths
}

func (s SpdxDoc) Tools() []GetTool {
	return s.SpdxTools
}

func (s SpdxDoc) Relations() []GetRelation {
	return s.Rels
}

func (s SpdxDoc) Logs() []string {
	return nil
}

func (s SpdxDoc) Lifecycles() []string {
	return []string{s.Lifecycle}
}

func (s SpdxDoc) Manufacturer() GetManufacturer {
	return nil
}

func (s SpdxDoc) Supplier() GetSupplier {
	return nil
}

func (s SpdxDoc) GetRelationships(componentID string) []string {
	return s.Dependencies[componentID]
}


func (s SpdxDoc) GetComposition(componentID string) string {
	return s.composition[componentID]
}

func (s SpdxDoc) Vulnerabilities() []GetVulnerabilities {
	return s.Vuln
}

func (s SpdxDoc) Signature() GetSignature {
	// SPDX does not support signatures in its specification
	return nil
}

func (s SpdxDoc) SchemaValidation() bool {
	return s.spdxValidSchema
}

func (s *SpdxDoc) parse() {
	s.parseDoc()
	s.parseSpec()
	s.parseAuthors()
	s.parseTool()
	s.parsePrimaryCompAndRelationships()
	s.parseComps()
}

func (s *SpdxDoc) parseDoc() {
	log := logger.FromContext(s.config.Context)

	if s.doc == nil {
		log.Debug("spdx doc is not parsable")
		return
	}
	if s.doc.CreationInfo != nil {
		if comment := s.doc.CreationInfo.CreatorComment; comment != "" {
			s.Lifecycle = comment
		}
	}
}

func (s *SpdxDoc) parseSpec() {
	sp := NewSpec()
	sp.Format = string(s.format)
	sp.Version = s.doc.SPDXVersion

	if s.doc.CreationInfo != nil {
		for _, c := range s.doc.CreationInfo.Creators {
			ctType := strings.ToLower(c.CreatorType)
			if ctType == "organization" {
				sp.Organization = c.Creator
			}
		}
		sp.Comment = s.doc.CreationInfo.CreatorComment
	}

	sp.Spdxid = string(s.doc.SPDXIdentifier)
	sp.Comment = s.doc.CreationInfo.CreatorComment

	sp.SpecType = string(SBOMSpecSPDX)
	sp.Name = s.doc.DocumentName

	if s.doc.ExternalDocumentReferences != nil {
		for _, bom := range s.doc.ExternalDocumentReferences {
			sp.ExternalDocReference = append(sp.ExternalDocReference, bom.URI)
		}
	}

	sp.isReqFieldsPresent = s.requiredFields()

	if s.doc.CreationInfo != nil {
		sp.CreationTimestamp = s.doc.CreationInfo.Created
		// sp.created = s.doc.CreationInfo.Created
		sp.Comment = s.doc.CreationInfo.CreatorComment
	}

	lics := licenses.LookupExpression(s.doc.DataLicense, nil)

	sp.Licenses = append(sp.Licenses, lics...)

	sp.Namespace = s.doc.DocumentNamespace

	if s.doc.DocumentNamespace != "" {
		sp.URI = s.doc.DocumentNamespace
	}
	s.Vuln = nil

	s.SpdxSpec = sp
}

func (s *SpdxDoc) parseComps() {
	s.Comps = []GetComponent{}

	for index, sc := range s.doc.Packages {
		nc := NewComponent()

		nc.Version = sc.PackageVersion
		nc.Name = sc.PackageName
		nc.Purpose = sc.PrimaryPackagePurpose
		nc.Spdxid = string(sc.PackageSPDXIdentifier)
		nc.CopyRight = sc.PackageCopyrightText
		nc.FileAnalyzed = sc.FilesAnalyzed
		nc.isReqFieldsPresent = s.pkgRequiredFields(index)
		nc.Purls = s.purls(index)
		nc.Cpes = s.cpes(index)
		nc.OmniID = nil
		nc.Swhid = nil
		nc.Swid = nil
		nc.Checksums = s.checksums(index)
		nc.ExternalRefs = s.externalRefs(index)
		nc.Licenses = s.licenses(index)
		nc.DeclaredLicense = s.declaredLicenses(index)
		nc.ConcludedLicense = s.concludedLicenses(index)
		nc.ID = nc.Spdxid
		nc.PackageLicenseConcluded = sc.PackageLicenseConcluded
		if strings.Contains(s.PrimaryComponent.ID, string(sc.PackageSPDXIdentifier)) {
			nc.PrimaryCompt = s.PrimaryComponent
		}

		manu := s.getManufacturer(index)
		if manu != nil {
			nc.manufacturer = *manu
		}

		supp := s.getSupplier(index)
		if supp != nil {
			nc.Supplier = *supp
		}

		auth := s.getAuthor(index)
		if supp != nil {
			nc.Athrs = auth
		}

		// https://github.com/spdx/ntia-conformance-checker/issues/100
		// Add spdx support to check both supplier and originator
		if supp == nil && manu != nil {
			nc.Supplier.Name = manu.Name
			nc.Supplier.Email = manu.Email
		}

		if sc.PackageVerificationCode != nil {
			nc.sourceCodeHash = sc.PackageVerificationCode.Value
		}

		nc.SourceCodeURL = sc.PackageSourceInfo

		nc.DownloadLocation = sc.PackageDownloadLocation

		nc.isPrimary = s.PrimaryComponent.ID == string(sc.PackageSPDXIdentifier)

		// fromRelsPresent := func(rels []GetRelation, id string) bool {
		// 	for _, r := range rels {
		// 		if strings.Contains(r.GetFrom(), id) {
		// 			return true
		// 		}
		// 	}
		// 	return false
		// }

		// nc.hasRelationships = fromRelsPresent(s.Rels, string(sc.PackageSPDXIdentifier))
		// nc.RelationshipState = "not-specified"
		nc.HasRelationships, nc.Count, nc.Dep = getComponentDependencies(s, nc.Spdxid)

		s.Comps = append(s.Comps, nc)
	}
}

func (s *SpdxDoc) parseAuthors() {
	s.Auths = []GetAuthor{}

	if s.doc.CreationInfo == nil {
		return
	}

	for _, c := range s.doc.CreationInfo.Creators {
		ctType := strings.ToLower(c.CreatorType)
		if ctType == "tool" {
			continue
		}
		a := Author{}

		entity := parser.ParseEntity(fmt.Sprintf("%s: %s", c.CreatorType, c.Creator))
		if entity != nil {
			a.Name = entity.Name
			a.Email = entity.Email
			a.AuthorType = ctType
			s.Auths = append(s.Auths, a)
		}
	}
}

// return true if a component has DEPENDS_ON relationship
func getComponentDependencies(s *SpdxDoc, componentID string) (bool, int, []string) {
	newID := "SPDXRef-" + componentID
	count := 0
	deps := make([]string, 0, len(s.doc.Relationships))
	for _, r := range s.doc.Relationships {
		// some sbom generating tools specify relationship type as contain and some as depends-on
		if strings.ToUpper(r.Relationship) == spdx.RelationshipDependsOn || strings.ToUpper(r.Relationship) == spdx.RelationshipContains {
			aBytes, err := r.RefA.MarshalJSON()
			if err != nil {
				continue
			}

			bBytes, err := r.RefB.MarshalJSON()
			if err != nil {
				continue
			}

			if parser.CleanKey(string(aBytes)) == newID {
				deps = append(deps, string(bBytes))
				count++
			}
		}
	}

	return count > 0, count, deps
}

func (s *SpdxDoc) parsePrimaryCompAndRelationships() {
	s.Dependencies = make(map[string][]string)
	var err error
	var aBytes, bBytes []byte
	var primaryComponent string
	var totalDependencies int

	for _, r := range s.doc.Relationships {
		// spdx_common.TypeRelationshipDescribe
		if strings.ToUpper(r.Relationship) == "DESCRIBES" {
			bBytes, err = r.RefB.MarshalJSON()
			if err != nil {
				continue
			}
			primaryComponent = parser.CleanKey(string(bBytes))
			s.PrimaryComponent.ID = primaryComponent
			s.PrimaryComponent.Present = true
			modified := strings.TrimPrefix(primaryComponent, "SPDXRef-")

			for _, pack := range s.doc.Packages {
				if string(pack.PackageSPDXIdentifier) == modified {
					s.PrimaryComponent.Name = pack.PackageName
					s.PrimaryComponent.Version = pack.PackageVersion
				}
			}
		}
	}

	for _, r := range s.doc.Relationships {
		if strings.ToUpper(r.Relationship) == spdx_common.TypeRelationshipContains {
			aBytes, err = r.RefA.MarshalJSON()
			if err != nil {
				continue
			}
			bBytes, err = r.RefB.MarshalJSON()
			if err != nil {
				continue
			}
			if parser.CleanKey(string(aBytes)) == s.PrimaryComponent.ID {
				totalDependencies++
				s.PrimaryComponent.HasDependency = true
				s.PrimaryComponent.AllDependencies = append(s.PrimaryComponent.AllDependencies, parser.CleanKey(string(bBytes)))
				s.Dependencies[parser.CleanKey(string(aBytes))] = append(s.Dependencies[parser.CleanKey(string(aBytes))], parser.CleanKey(string(bBytes)))

			} else {
				s.Dependencies[parser.CleanKey(string(aBytes))] = append(s.Dependencies[parser.CleanKey(string(aBytes))], parser.CleanKey(string(bBytes)))
			}
		}
	}
	s.PrimaryComponent.Dependecies = totalDependencies
}

// creationInfo.Creators.Tool
// Also create for org: , creationInfo.Creators.Organization
func (s *SpdxDoc) parseTool() {
	s.SpdxTools = []GetTool{}

	if s.doc.CreationInfo == nil {
		return
	}

	// https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field
	// spdx2.3 spec says If the SPDX document was created using a software tool,
	// indicate the name and version for that tool
	extractVersion := func(inputName string) (string, string) {
		// Split the input string by "-"
		parts := strings.Split(inputName, "-")

		// if there are no "-" its a bad string
		if len(parts) == 1 {
			return inputName, ""
		}
		// The last element after splitting is the version
		version := parts[len(parts)-1]

		// The name is everything before the last element
		name := strings.Join(parts[:len(parts)-1], "-")

		// check if version has atleast one-digit
		// if not, then it is not a version
		for _, r := range version {
			if unicode.IsDigit(r) {
				return name, version
			}
		}

		// This is a bad case
		return inputName, ""
	}

	for _, c := range s.doc.CreationInfo.Creators {
		ctType := strings.ToLower(c.CreatorType)
		if ctType != "tool" {
			continue
		}
		t := Tool{}
		t.Name, t.Version = extractVersion(c.Creator)
		s.SpdxTools = append(s.SpdxTools, t)
	}
}


func (s *SpdxDoc) requiredFields() bool {
	log := logger.FromContext(s.config.Context)

	if s.doc == nil {
		log.Debug("spdx doc is not parsable")
		return false
	}

	hasRequiredFields := true

	// Creation info is a required section
	if s.doc.CreationInfo == nil {
		log.Debug("spdx doc is missing creation info")
		hasRequiredFields = false
	} else {
		// Identify who (or what, in the case of a tool) created the SPDX document.
		if len(s.doc.CreationInfo.Creators) == 0 {
			log.Debug("spdx doc is missing creators")
			hasRequiredFields = false
		}

		// Identify when the SPDX document was originally created.
		if s.doc.CreationInfo.Created == "" {
			log.Debug("spdx doc is missing created timestamp")
			hasRequiredFields = false
		}
	}

	// SPDXVersion is required
	if s.doc.SPDXVersion == "" {
		log.Debug("spdx doc is missing SPDXVersion")
		hasRequiredFields = false
	}

	// data license is required
	if s.doc.DataLicense == "" {
		log.Debug("spdx doc is missing DataLicense")
		hasRequiredFields = false
	}

	// Identify the current SPDX document which may be referenced in relationships
	// by other files, packages internally and documents externally
	if s.doc.SPDXIdentifier == "" {
		log.Debug("spdx doc is missing SPDXIdentifier")
		hasRequiredFields = false
	}

	// Identify name of this document as designated by creator
	if s.doc.DocumentName == "" {
		log.Debug("spdx doc is missing DocumentName")
		hasRequiredFields = false
	}

	// The URI provides an unambiguous mechanism for other SPDX documents to reference SPDX elements within this SPDX document
	if s.doc.DocumentNamespace == "" {
		log.Debug("spdx doc is missing Document Namespace")
		hasRequiredFields = false
	}

	return hasRequiredFields
}

func (s *SpdxDoc) pkgRequiredFields(index int) bool {
	log := logger.FromContext(s.config.Context)

	pkg := s.doc.Packages[index]
	hasRequiredFields := true

	if pkg.PackageName == "" {
		log.Debugf("spdx doc pkg %s at index %d missing name", pkg.PackageSPDXIdentifier, index)
		hasRequiredFields = false
	}

	if pkg.PackageSPDXIdentifier == "" {
		log.Debugf("spdx doc pkg %s at index %d missing identifier", pkg.PackageName, index)
		hasRequiredFields = false
	}

	// What is the correct behaviour for NONE and NOASSERTION?
	if pkg.PackageDownloadLocation == "" {
		log.Debugf("spdx doc pkg %s at index %d missing downloadLocation", pkg.PackageName, index)
		hasRequiredFields = false
	}

	if pkg.FilesAnalyzed && pkg.PackageVerificationCode == nil {
		log.Debugf("spdx doc pkg %s at index %d missing packageVerificationCode", pkg.PackageName, index)
		hasRequiredFields = false
	}
	return hasRequiredFields
}

func (s *SpdxDoc) purls(index int) []purl.PURL {
	log := logger.FromContext(s.config.Context)

	pkg := s.doc.Packages[index]

	if len(pkg.PackageExternalReferences) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no purls found", pkg.PackageName, index)
		return []purl.PURL{}
	}

	urls := make([]purl.PURL, 0, len(pkg.PackageExternalReferences))
	for _, p := range pkg.PackageExternalReferences {
		if strings.ToLower(p.RefType) == spdx_common.TypePackageManagerPURL {
			prl := purl.NewPURL(p.Locator)
			if prl.Valid() {
				urls = append(urls, prl)
			} else {
				log.Debugf("spdx doc pkg %s at index %d invalid purl found", pkg.PackageName, index)
			}
		}
	}

	if len(urls) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no purls found", pkg.PackageName, index)
	}

	return urls
}

func (s *SpdxDoc) cpes(index int) []cpe.CPE {
	log := logger.FromContext(s.config.Context)

	pkg := s.doc.Packages[index]
	if len(pkg.PackageExternalReferences) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no cpes found", pkg.PackageName, index)
		return []cpe.CPE{}
	}

	urls := make([]cpe.CPE, 0, len(pkg.PackageExternalReferences))
	for _, p := range pkg.PackageExternalReferences {
		if p.RefType == spdx_common.TypeSecurityCPE23Type || p.RefType == spdx_common.TypeSecurityCPE22Type {
			cpeV := cpe.NewCPE(p.Locator)
			if cpeV.Valid() {
				urls = append(urls, cpeV)
			} else {
				log.Debugf("spdx doc pkg %s at index %d invalid cpes found", pkg.PackageName, index)
			}
		}
	}
	if len(urls) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no cpes found", pkg.PackageName, index)
	}

	return urls
}

func (s *SpdxDoc) checksums(index int) []GetChecksum {
	log := logger.FromContext(s.config.Context)

	pkg := s.doc.Packages[index]

	if len(pkg.PackageChecksums) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no checksum found", pkg.PackageName, index)
		return []GetChecksum{}
	}

	chks := make([]GetChecksum, 0, len(pkg.PackageChecksums))
	for _, c := range pkg.PackageChecksums {
		ck := Checksum{}
		ck.Alg = string(c.Algorithm)
		ck.Content = c.Value
		chks = append(chks, ck)
	}

	return chks
}

func (s *SpdxDoc) externalRefs(index int) []GetExternalReference {
	log := logger.FromContext(s.config.Context)

	pkg := s.doc.Packages[index]

	if len(pkg.PackageExternalReferences) == 0 {
		log.Debugf("spdx doc pkg %s at index %d no externalReferences found", pkg.PackageName, index)
		return []GetExternalReference{}
	}

	extRefs := make([]GetExternalReference, 0, len(pkg.PackageExternalReferences))
	for _, ext := range pkg.PackageExternalReferences {
		extRef := ExternalReference{}
		extRef.RefType = ext.RefType
		extRef.RefLocator = ext.Locator
		extRefs = append(extRefs, extRef)
	}

	return extRefs
}

func (s *SpdxDoc) licenses(index int) []licenses.License {
	lics := []licenses.License{}

	pkg := s.doc.Packages[index]

	otherLicenses := lo.Map(s.doc.OtherLicenses, func(l *spdx.OtherLicense, _ int) licenses.License {
		return licenses.CreateCustomLicense(l.LicenseIdentifier, l.LicenseName)
	})

	if pkg.PackageLicenseConcluded != "" {
		conLics := licenses.LookupExpression(pkg.PackageLicenseConcluded, otherLicenses)
		if len(conLics) > 0 {
			lics = append(lics, conLics...)
			return lics
		}
	}

	if pkg.PackageLicenseDeclared != "" {
		decLics := licenses.LookupExpression(pkg.PackageLicenseDeclared, otherLicenses)
		if len(decLics) > 0 {
			lics = append(lics, decLics...)
			return lics
		}
	}

	return lics
}

func (s *SpdxDoc) declaredLicenses(index int) []licenses.License {
	lics := []licenses.License{}

	pkg := s.doc.Packages[index]

	otherLicenses := lo.Map(s.doc.OtherLicenses, func(l *spdx.OtherLicense, _ int) licenses.License {
		return licenses.CreateCustomLicense(l.LicenseIdentifier, l.LicenseName)
	})

	if pkg.PackageLicenseDeclared != "" {
		decLics := licenses.LookupExpression(pkg.PackageLicenseDeclared, otherLicenses)
		if len(decLics) > 0 {
			lics = append(lics, decLics...)
			return lics
		}
	}

	return lics
}

func (s *SpdxDoc) concludedLicenses(index int) []licenses.License {
	lics := []licenses.License{}

	pkg := s.doc.Packages[index]

	otherLicenses := lo.Map(s.doc.OtherLicenses, func(l *spdx.OtherLicense, _ int) licenses.License {
		return licenses.CreateCustomLicense(l.LicenseIdentifier, l.LicenseName)
	})

	if pkg.PackageLicenseConcluded != "" {
		conLics := licenses.LookupExpression(pkg.PackageLicenseConcluded, otherLicenses)
		if len(conLics) > 0 {
			lics = append(lics, conLics...)
			return lics
		}
	}

	return lics
}

// getManufacturer for spdx checks for packageOriginator
func (s *SpdxDoc) getManufacturer(index int) *Manufacturer {
	pkg := s.doc.Packages[index]

	if pkg.PackageOriginator == nil {
		return nil
	}

	if strings.ToLower(pkg.PackageOriginator.Originator) == "noassertion" {
		return nil
	}

	entity := parser.ParseEntity(fmt.Sprintf("%s: %s", pkg.PackageOriginator.OriginatorType, pkg.PackageOriginator.Originator))
	if entity == nil {
		return nil
	}

	return &Manufacturer{
		Name:  entity.Name,
		Email: entity.Email,
	}
}

// getAuthor in spdx checks for packageOriginator
func (s *SpdxDoc) getAuthor(index int) []GetAuthor {
	authors := []GetAuthor{}
	var a Author
	pkg := s.doc.Packages[index]

	if pkg.PackageOriginator == nil {
		return nil
	}

	entity := parser.ParseEntity(fmt.Sprintf("%s: %s", pkg.PackageOriginator.OriginatorType, pkg.PackageOriginator.Originator))
	if entity == nil {
		return nil
	}

	a.Name = entity.Name
	a.Email = entity.Email

	authors = append(authors, a)
	return authors
}

// https://github.com/spdx/ntia-conformance-checker/issues/100
// Add spdx support to check both supplier and originator
func (s *SpdxDoc) getSupplier(index int) *Supplier {
	pkg := s.doc.Packages[index]

	if pkg.PackageSupplier == nil {
		return nil
	}

	entity := parser.ParseEntity(fmt.Sprintf("%s: %s", pkg.PackageSupplier.SupplierType, pkg.PackageSupplier.Supplier))
	if entity == nil {
		return nil
	}

	return &Supplier{
		Name:  entity.Name,
		Email: entity.Email,
	}
}

