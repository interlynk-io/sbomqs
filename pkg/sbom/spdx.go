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
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/validation"
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
	spdxSpecVersions   = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3"}
	spdxPrimaryPurpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "source", "archive", "file", "install", "other"}
)

type SpdxDoc struct {
	doc              *spdx.Document
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
}

func newSPDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion, _ Signature) (Document, error) {
	log := logger.FromContext(ctx)
	var err error

	log.Debug("Constructing new instance of spdx")

	// Read the content for manual parsing if needed
	rawContent, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Reset the reader for the decoder
	reader := bytes.NewReader(rawContent)

	var d *spdx.Document

	switch format {
	case FileFormatJSON:
		d, err = spdx_json.Read(reader)
	case FileFormatTagValue:
		d, err = spdx_tv.Read(reader)
	case FileFormatYAML:
		d, err = spdx_yaml.Read(reader)
	case FileFormatRDF:
		d, err = spdx_rdf.Read(reader)
	default:
		err = fmt.Errorf("unsupported spdx format %s", string(format))
	}

	if err != nil {
		return nil, err
	}

	doc := &SpdxDoc{
		doc:        d,
		format:     format,
		ctx:        ctx,
		version:    version,
		rawContent: rawContent,
	}

	doc.parse()
	for _, l := range doc.Logs() {
		log.Debug(l)
	}

	return doc, err
}

func (s SpdxDoc) PrimaryComp() GetPrimaryComponentInfo {
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

func (s SpdxDoc) GetRelationships() []GetRelationship {
	return s.Relationships
}

func (s SpdxDoc) GetOutgoingRelations(compID string) []GetRelationship {
	out := make([]GetRelationship, 0)
	for _, r := range s.Relationships {
		if r.GetFrom() == compID {
			out = append(out, r)
		}
	}
	return out
}

func (s SpdxDoc) GetDirectDependencies(compID string, relTypes ...string) []GetComponent {
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

func relTypeAllowed(relType string, allowedType []string) bool {
	if len(allowedType) == 0 {
		return true
	}

	for _, t := range allowedType {
		if strings.EqualFold(relType, t) {
			return true
		}
	}
	return false
}

func (s SpdxDoc) Logs() []string {
	return s.logs
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

// Helper function to clean up keys
func CleanKey(key string) string {
	return strings.Trim(key, `"`)
}

func (s SpdxDoc) Composition() []GetComposition {
	return s.compositions
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
	s.parseSchemaValidation()
	s.parseAuthors()
	s.parseTool()
	s.parsePrimaryComponent()
	s.parseRelationships()
	s.parseComps()
}

func (s *SpdxDoc) parseDoc() {
	if s.doc == nil {
		s.addToLogs("cdx doc is not parsable")
		return
	}
	if comment := s.doc.CreationInfo.CreatorComment; comment != "" {
		s.Lifecycle = comment
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

func (s *SpdxDoc) parseSchemaValidation() {
	s.spdxValidSchema = false
	s.addToLogs("processing parseSchemaValidation")

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

func normalizeSpdxVersion(v string) string {
	// SPDX-2.3 → 2.3
	if strings.HasPrefix(v, "SPDX-") {
		return strings.TrimPrefix(v, "SPDX-")
	}
	return v
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
		nc.ID = string(sc.PackageSPDXIdentifier)
		nc.PackageLicenseConcluded = sc.PackageLicenseConcluded

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

		entity := parseEntity(fmt.Sprintf("%s: %s", c.CreatorType, c.Creator))
		if entity != nil {
			a.Name = entity.name
			a.Email = entity.email
			a.AuthorType = ctType
			s.Auths = append(s.Auths, a)
		}
	}
}

// parsePrimaryComponent
func (s *SpdxDoc) parsePrimaryComponent() {
	for _, r := range s.doc.Relationships {
		if strings.ToUpper(r.Relationship) != spdx_common.TypeRelationshipDescribe {
			continue
		}

		// DOCUMENT -> component
		bBytes, err := r.RefB.MarshalJSON()
		if err != nil {
			continue
		}

		id := CleanKey(string(bBytes))
		s.PrimaryComponent.Present = true

		// Resolve name/version from packages
		pkgID := strings.TrimPrefix(id, "SPDXRef-")
		s.PrimaryComponent.ID = pkgID
		for _, p := range s.doc.Packages {
			if string(p.PackageSPDXIdentifier) == pkgID {
				s.PrimaryComponent.Name = p.PackageName
				s.PrimaryComponent.Version = p.PackageVersion
				break
			}
		}
		break // assume single primary component
	}
}

// parseRelationships()
func (s *SpdxDoc) parseRelationships() {
	s.Relationships = make([]GetRelationship, 0, len(s.doc.Relationships))

	for _, r := range s.doc.Relationships {
		aBytes, err := r.RefA.MarshalJSON()
		if err != nil {
			continue
		}

		bBytes, err := r.RefB.MarshalJSON()
		if err != nil {
			continue
		}

		rel := Relationship{
			From: strings.TrimPrefix(CleanKey(string(aBytes)), "SPDXRef-"),
			To:   strings.TrimPrefix(CleanKey(string(bBytes)), "SPDXRef-"),
			Type: strings.ToUpper(r.Relationship),
		}

		s.Relationships = append(s.Relationships, rel)
	}
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

func (s *SpdxDoc) addToLogs(log string) {
	s.logs = append(s.logs, log)
}

func (s *SpdxDoc) requiredFields() bool {
	if s.doc == nil {
		s.addToLogs("spdx doc is not parsable")
		return false
	}
	// Creation info is a required section
	if s.doc.CreationInfo == nil {
		s.addToLogs("spdx doc is missing creation info")
		return false
	}

	// SPDXVersion is required
	if s.doc.SPDXVersion == "" {
		s.addToLogs("spdx doc is missing SPDXVersion")
		return false
	}

	// data license is required
	if s.doc.DataLicense == "" {
		s.addToLogs("spdx doc is missing Datalicense")
		return false
	}
	// Identify the current SPDX document which may be referenced in relationships
	// by other files, packages internally and documents externally
	if s.doc.SPDXIdentifier == "" {
		s.addToLogs("spdx doc is missing SPDXIdentifier")
		return false
	}
	// Identify name of this document as designated by creator
	if s.doc.DocumentName == "" {
		s.addToLogs("spdx doc is missing DocumentName")
		return false
	}

	// The URI provides an unambiguous mechanism for other SPDX documents to reference SPDX elements within this SPDX document
	if s.doc.DocumentNamespace == "" {
		s.addToLogs("spdx doc is missing Document Namespace")
		return false
	}

	// Identify who (or what, in the case of a tool) created the SPDX document.
	if len(s.doc.CreationInfo.Creators) == 0 {
		s.addToLogs("spdx doc is missing creators")
		return false
	}

	// Identify when the SPDX document was originally created.
	if s.doc.CreationInfo.Created == "" {
		s.addToLogs("spdx doc is missing created timestamp")
		return false
	}
	return true
}

func (s *SpdxDoc) pkgRequiredFields(index int) bool {
	pkg := s.doc.Packages[index]

	if pkg.PackageName == "" {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing name", pkg.PackageSPDXIdentifier, index))
		return false
	}

	if pkg.PackageSPDXIdentifier == "" {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing identifier", pkg.PackageName, index))
		return false
	}

	// What is the correct behaviour for NONE and NOASSERTION?
	if pkg.PackageDownloadLocation == "" {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing downloadLocation", pkg.PackageName, index))
		return false
	}

	if pkg.FilesAnalyzed && pkg.PackageVerificationCode == nil {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing packageVerificationCode", pkg.PackageName, index))
		return false
	}
	return true
}

func (s *SpdxDoc) purls(index int) []purl.PURL {
	pkg := s.doc.Packages[index]

	if len(pkg.PackageExternalReferences) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no purls found", pkg.PackageName, index))
		return []purl.PURL{}
	}

	urls := make([]purl.PURL, 0, len(pkg.PackageExternalReferences))
	for _, p := range pkg.PackageExternalReferences {
		if strings.ToLower(p.RefType) == spdx_common.TypePackageManagerPURL {
			prl := purl.NewPURL(p.Locator)
			if prl.Valid() {
				urls = append(urls, prl)
			} else {
				s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d invalid purl found", pkg.PackageName, index))
			}
		}
	}

	if len(urls) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no purls found", pkg.PackageName, index))
	}

	return urls
}

func (s *SpdxDoc) cpes(index int) []cpe.CPE {
	pkg := s.doc.Packages[index]
	if len(pkg.PackageExternalReferences) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no cpes found", pkg.PackageName, index))
		return []cpe.CPE{}
	}

	urls := make([]cpe.CPE, 0, len(pkg.PackageExternalReferences))
	for _, p := range pkg.PackageExternalReferences {
		if p.RefType == spdx_common.TypeSecurityCPE23Type || p.RefType == spdx_common.TypeSecurityCPE22Type {
			cpeV := cpe.NewCPE(p.Locator)
			if cpeV.Valid() {
				urls = append(urls, cpeV)
			} else {
				s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d invalid cpes found", pkg.PackageName, index))
			}
		}
	}
	if len(urls) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no cpes found", pkg.PackageName, index))
	}

	return urls
}

func (s *SpdxDoc) checksums(index int) []GetChecksum {
	pkg := s.doc.Packages[index]

	if len(pkg.PackageChecksums) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no checksum found", pkg.PackageName, index))
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
	pkg := s.doc.Packages[index]

	if len(pkg.PackageExternalReferences) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no externalReferences found", pkg.PackageName, index))
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

	entity := parseEntity(fmt.Sprintf("%s: %s", pkg.PackageOriginator.OriginatorType, pkg.PackageOriginator.Originator))
	if entity == nil {
		return nil
	}

	return &Manufacturer{
		Name:  entity.name,
		Email: entity.email,
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

	entity := parseEntity(fmt.Sprintf("%s: %s", pkg.PackageOriginator.OriginatorType, pkg.PackageOriginator.Originator))
	if entity == nil {
		return nil
	}

	a.Name = entity.name
	a.Email = entity.email

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

	entity := parseEntity(fmt.Sprintf("%s: %s", pkg.PackageSupplier.SupplierType, pkg.PackageSupplier.Supplier))
	if entity == nil {
		return nil
	}

	return &Supplier{
		Name:  entity.name,
		Email: entity.email,
	}
}

type entity struct {
	name  string
	email string
}

func parseEntity(in string) *entity {
	if strings.HasPrefix(in, ":") {
		in = strings.TrimSpace(strings.TrimLeft(in, ":"))
	}

	if strings.ToUpper(in) == "NOASSERTION" || strings.ToUpper(in) == "NONE" {
		return &entity{name: in}
	}

	// Regex pattern to match organization or person and email
	pattern := `(Organization|Person)\s*:\s*([^(]+)\s*(?:\(\s*([^)]+)\s*\))?`
	regex := regexp.MustCompile(pattern)
	match := regex.FindStringSubmatch(in)

	if len(match) == 0 {
		return nil
	}

	name := strings.TrimSpace(match[2])
	var email string
	if len(match) > 3 {
		email = strings.TrimSpace(match[3])
	}

	entity := &entity{name: name, email: email}
	return entity
}
