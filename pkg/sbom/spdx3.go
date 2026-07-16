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
	"github.com/interlynk-io/spdx-zen/parse"
)

var spdx3SpecVersions = []string{"3.0", "3.0.1"}

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

	doc, err := parse.FromReader(reader)
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

	if s.doc.HasLifecycle() {
		lifecycleInfo := s.doc.GetLifecycleInfo()
		if sbomType, ok := lifecycleInfo["sbomType"]; ok {
			s.Lifecycle = sbomType
		}
	}
}

func (s *Spdx3Doc) parseSpec() {
	sp := NewSpec()

	sp.Format = string(s.format)
	sp.SpecType = string(SBOMSpecSPDX)

	version := s.doc.SpecVersion()
	if strings.HasPrefix(version, "SPDX-") {
		sp.Version = strings.TrimPrefix(version, "SPDX-")
	} else {
		sp.Version = version
	}

	sp.Name = s.doc.Name()
	sp.Spdxid = s.doc.SpdxID()

	if s.doc.CreationInfo() != nil {
		ci := s.doc.CreationInfo()

		// Creation timestamp - format time.Time to RFC3339 string
		if !ci.Created.IsZero() {
			sp.CreationTimestamp = ci.Created.Format(time.RFC3339)
		}

		sp.Comment = ci.Comment

		// Organization - find in CreatedBy
		for _, creator := range ci.CreatedBy {
			if creator.Type == "Organization" {
				sp.Organization = creator.Name
				break
			}
		}
	}

	nsMap := s.doc.NamespaceMap()
	if len(nsMap) > 0 {
		// Use first namespace entry
		for _, ns := range nsMap {
			sp.Namespace = ns
			sp.URI = ns
			break
		}
	}

	// Data license
	dataLicense := s.doc.DataLicense()
	if dataLicense != "" {
		lics := licenses.LookupExpression(dataLicense, nil)
		sp.Licenses = append(sp.Licenses, lics...)
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

	if s.doc.CreationInfo() == nil {
		return
	}

	for _, agent := range s.doc.Authors() {
		agentType := strings.ToLower(agent.Type)
		if agentType == "tool" || agentType == "softwareagent" {
			continue
		}

		a := Author{}
		a.Name = agent.Name
		a.Email = agent.Email

		switch agentType {
		case "Person":
			a.AuthorType = "person"

		case "Organization":
			a.AuthorType = "organization"

		default:
			a.AuthorType = agentType
		}

		s.Auths = append(s.Auths, a)
	}
}

func (s *Spdx3Doc) parseTool() {
	s.SpdxTools = []GetTool{}

	if s.doc.CreationInfo() == nil {
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

	for _, agent := range s.doc.AllTools() {
		t := Tool{}
		t.Name, t.Version = extractVersion(agent.Name)
		s.SpdxTools = append(s.SpdxTools, t)
	}
}

func (s *Spdx3Doc) parsePrimaryComponent() {
	pkg := s.doc.PrimaryPackage()
	if pkg == nil {
		return
	}

	s.PrimaryComponent.Present = s.doc.HasPrimaryPackage()
	s.PrimaryComponent.ID = strings.TrimPrefix(pkg.SpdxID, "SPDXRef-")
	s.PrimaryComponent.Name = pkg.Name
	s.PrimaryComponent.Version = pkg.Version
	s.PrimaryComponent.Type = pkg.PrimaryPurpose
}

func (s *Spdx3Doc) parseRelationships() {
	s.Relationships = make([]GetRelationship, 0)

	for _, rel := range s.doc.Relationships() {
		// Skip "describes" relationships (document -> primary component)
		if rel.RelationshipType == "describes" {
			continue
		}

		// SPDX 3.0 relationships can have multiple targets
		// Flatten them into individual From->To relationships
		for _, to := range rel.To {
			r := Relationship{
				From: strings.TrimPrefix(rel.From, "SPDXRef-"),
				To:   strings.TrimPrefix(to, "SPDXRef-"),
				Type: strings.ToUpper(rel.RelationshipType),
			}
			s.Relationships = append(s.Relationships, r)
		}
	}
}

func (s *Spdx3Doc) parseComps() {
	s.Comps = []GetComponent{}

	for _, pkg := range s.doc.Packages() {
		nc := NewComponent()

		nc.Version = pkg.Version
		nc.Name = pkg.Name
		nc.Purpose = pkg.PrimaryPurpose
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
		nc.ID = pkg.SpdxID
		if pkg.LicenseInfo != nil {
			nc.PackageLicenseConcluded = pkg.LicenseInfo.Concluded
		}

		// Supplier
		if pkg.Supplier != nil {
			nc.Supplier = Supplier{
				Name:  pkg.Supplier.Name,
				Email: pkg.Supplier.Email,
				URL:   pkg.Supplier.URL,
			}
		}

		// Manufacturer (Originator in SPDX)
		if len(pkg.Originator) > 0 {
			orig := pkg.Originator[0]
			nc.Manufacture = Manufacturer{
				Name:  orig.Name,
				Email: orig.Email,
				URL:   orig.URL,
			}
		}

		// If no supplier but has manufacturer, copy manufacturer to supplier
		if pkg.Supplier == nil && len(pkg.Originator) > 0 {
			nc.Supplier = Supplier{
				Name:  nc.Manufacture.Name,
				Email: nc.Manufacture.Email,
				URL:   nc.Manufacture.URL,
			}
		}

		nc.SourceCodeURL = pkg.GetPrimarySourceCodeURL()
		nc.DownloadLocation = pkg.DownloadLocation

		s.Comps = append(s.Comps, nc)

	}
}

// Helper methods for parseComps

func (s *Spdx3Doc) pkgRequiredFields(pkg *parse.PackageInfo) bool {
	// Check required fields for NTIA minimum elements
	if pkg.Name == "" {
		return false
	}
	if pkg.Supplier == nil || parse.IsNoAssertion(pkg.Supplier.Name) {
		return false
	}
	return true
}

func (s *Spdx3Doc) purls(pkg *parse.PackageInfo) []purl.PURL {
	urls := make([]purl.PURL, 0)
	for _, purlStr := range pkg.PURLs() {
		prl := purl.NewPURL(purlStr)
		if prl.Valid() {
			urls = append(urls, prl)
		}
	}
	return urls
}

func (s *Spdx3Doc) cpes(pkg *parse.PackageInfo) []cpe.CPE {
	urls := make([]cpe.CPE, 0)
	for _, cpeStr := range pkg.CPEs() {
		cpeV := cpe.NewCPE(cpeStr)
		if cpeV.Valid() {
			urls = append(urls, cpeV)
		}
	}
	return urls
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
	return extRefs
}

func (s *Spdx3Doc) licenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}
	if pkg.LicenseInfo != nil && pkg.LicenseInfo.Concluded != "" {
		lics = append(lics, licenses.LookupExpression(pkg.LicenseInfo.Concluded, nil)...)
	}
	return lics
}

func (s *Spdx3Doc) declaredLicenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}

	// First check direct LicenseInfo field
	if pkg.LicenseInfo != nil && pkg.LicenseInfo.Declared != "" {
		lics = append(lics, licenses.LookupExpression(pkg.LicenseInfo.Declared, nil)...)
	}

	// Also check SPDX 3.0 license relationships
	if s.doc != nil {
		for _, rel := range s.doc.DeclaredLicenseFor(pkg.SpdxID) {
			for _, to := range rel.To {
				// Resolve the license reference
				if resolved := s.doc.ResolveLicenseRef(to); resolved != "" && resolved != "NOASSERTION" {
					lics = append(lics, licenses.LookupExpression(resolved, nil)...)
				}
			}
		}
	}

	return lics
}

func (s *Spdx3Doc) concludedLicenses(pkg *parse.PackageInfo) []licenses.License {
	lics := []licenses.License{}

	// First check direct LicenseInfo field
	if pkg.LicenseInfo != nil && pkg.LicenseInfo.Concluded != "" {
		lics = append(lics, licenses.LookupExpression(pkg.LicenseInfo.Concluded, nil)...)
	}

	// Also check SPDX 3.0 license relationships
	if s.doc != nil {
		for _, rel := range s.doc.ConcludedLicenseFor(pkg.SpdxID) {
			for _, to := range rel.To {
				// Resolve the license reference
				if resolved := s.doc.ResolveLicenseRef(to); resolved != "" && resolved != "NOASSERTION" {
					lics = append(lics, licenses.LookupExpression(resolved, nil)...)
				}
			}
		}
	}

	return lics
}

func (s *Spdx3Doc) parseFiles() {
	s.File = []GetComponent{}

	for _, f := range s.doc.Files() {
		nc := NewComponent()

		nc.Name = f.Name
		nc.Spdxid = f.SpdxID
		nc.ID = f.SpdxID
		nc.PackageFilename = f.Name

		// File checksums/hashes
		if len(f.Hashes) > 0 {
			chks := make([]GetChecksum, 0, len(f.Hashes))
			for _, h := range f.Hashes {
				ck := Checksum{
					Alg:     h.Algorithm,
					Content: h.Value,
				}
				chks = append(chks, ck)
			}
			nc.Checksums = chks
		}

		// File purpose (SPDX 3.0: PrimaryPurpose, AdditionalPurpose)
		nc.Purpose = f.PrimaryPurpose

		// File comment
		nc.CopyRight = f.Comment

		// External references (if any)
		if len(f.ExternalRefs) > 0 {
			extRefs := make([]GetExternalReference, 0, len(f.ExternalRefs))
			for _, ext := range f.ExternalRefs {
				extRef := ExternalReference{
					RefType:    ext.Type,
					RefLocator: ext.Locator,
				}
				extRefs = append(extRefs, extRef)
			}
			nc.ExternalRefs = extRefs
		}

		s.File = append(s.File, nc)
	}
}
