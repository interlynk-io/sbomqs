// Copyright 2023 Interlynk.io
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
	"regexp"
	"strings"
	"unicode"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/samber/lo"
	spdx_json "github.com/spdx/tools-golang/json"
	spdx_rdf "github.com/spdx/tools-golang/rdf"
	spdx_common "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	spdx_tv "github.com/spdx/tools-golang/tagvalue"
	spdx_yaml "github.com/spdx/tools-golang/yaml"
)

var spdx_file_formats = []string{"json", "yaml", "rdf", "tag-value"}
var spdx_spec_versions = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3"}
var spdx_primary_purpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "source", "archive", "file", "install", "other"}

type spdxDoc struct {
	doc                *v2_3.Document
	format             FileFormat
	ctx                context.Context
	spec               *spec
	comps              []Component
	authors            []Author
	tools              []Tool
	rels               []Relation
	logs               []string
	primaryComponent   bool
	primaryComponentId string
	lifecycles         string
}

func newSPDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat) (Document, error) {
	_ = logger.FromContext(ctx)

	f.Seek(0, io.SeekStart)

	var d *v2_3.Document
	var err error

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
		return nil, err
	}

	doc := &spdxDoc{
		doc:    d,
		format: format,
		ctx:    ctx,
	}

	doc.parse()

	return doc, err
}

func (s spdxDoc) Spec() Spec {
	return *s.spec
}

func (s spdxDoc) Components() []Component {
	return s.comps
}

func (s spdxDoc) Authors() []Author {
	return s.authors
}

func (s spdxDoc) Tools() []Tool {
	return s.tools
}

func (s spdxDoc) Relations() []Relation {
	return s.rels
}
func (s spdxDoc) Logs() []string {
	return s.logs
}

func (s spdxDoc) PrimaryComponent() bool {
	return s.primaryComponent
}

func (s spdxDoc) Lifecycles() []string {
	return []string{s.lifecycles}
}

func (s spdxDoc) Manufacturer() Manufacturer {
	return nil
}

func (s spdxDoc) Supplier() Supplier {
	return nil
}

func (s *spdxDoc) parse() {
	s.parseSpec()
	s.parseAuthors()
	s.parseTool()
	s.parseRels()
	s.parsePrimaryComponent()
	s.parseComps()
}

func (s *spdxDoc) parseSpec() {
	sp := newSpec()
	sp.format = string(s.format)
	sp.version = s.doc.SPDXVersion
	sp.name = string(SBOMSpecSPDX)
	sp.isReqFieldsPresent = s.requiredFields()
	if s.doc.CreationInfo != nil {
		sp.creationTimestamp = s.doc.CreationInfo.Created
	}

	lics := licenses.LookupExpression(s.doc.DataLicense, nil)

	sp.licenses = append(sp.licenses, lics...)

	sp.namespace = s.doc.DocumentNamespace

	if s.doc.DocumentNamespace != "" {
		sp.uri = s.doc.DocumentNamespace
	}

	s.spec = sp
}

func (s *spdxDoc) parseComps() {
	s.comps = []Component{}

	for index, sc := range s.doc.Packages {
		nc := newComponent()

		nc.version = sc.PackageVersion
		nc.name = sc.PackageName
		nc.purpose = sc.PrimaryPackagePurpose
		nc.isReqFieldsPresent = s.pkgRequiredFields(index)
		nc.purls = s.purls(index)
		nc.cpes = s.cpes(index)
		nc.checksums = s.checksums(index)
		nc.licenses = s.licenses(index)
		nc.id = string(sc.PackageSPDXIdentifier)

		manu := s.getManufacturer(index)
		if manu != nil {
			nc.manufacturer = *manu
		}

		supp := s.getSupplier(index)
		if supp != nil {
			nc.supplier = *supp
		}
		nc.supplierName = s.addSupplierName(index)
		nc.sourceCodeHash = sc.PackageVerificationCode.Value

		//nc.sourceCodeUrl //no conlusive way to get this from SPDX
		nc.downloadLocation = sc.PackageDownloadLocation

		nc.isPrimary = s.primaryComponentId == string(sc.PackageSPDXIdentifier)

		fromRelsPresent := func(rels []Relation, id string) bool {
			for _, r := range rels {
				if r.From() == id {
					return true
				}
			}
			return false
		}

		nc.hasRelationships = fromRelsPresent(s.rels, string(sc.PackageSPDXIdentifier))
		nc.relationshipState = "not-specified"

		s.comps = append(s.comps, nc)
	}
}

func (s *spdxDoc) parseAuthors() {
	s.authors = []Author{}

	if s.doc.CreationInfo == nil {
		return
	}

	for _, c := range s.doc.CreationInfo.Creators {
		ctType := strings.ToLower(c.CreatorType)
		if ctType == "tool" {
			continue
		}
		a := author{}

		entity := parseEntity(fmt.Sprintf("%s: %s", c.CreatorType, c.Creator))
		if entity != nil {
			a.name = entity.name
			a.email = entity.email
			a.authorType = ctType
			s.authors = append(s.authors, a)
		}
	}
}

func (s *spdxDoc) parseRels() {
	s.rels = []Relation{}

	var err error
	var aBytes, bBytes []byte

	for _, r := range s.doc.Relationships {
		nr := relation{}
		switch strings.ToUpper(r.Relationship) {
		case spdx_common.TypeRelationshipDescribe:
			fallthrough
		case spdx_common.TypeRelationshipContains:
			fallthrough
		case spdx_common.TypeRelationshipDependsOn:
			aBytes, err = r.RefA.MarshalJSON()
			if err != nil {
				continue
			}

			bBytes, err = r.RefB.MarshalJSON()
			if err != nil {
				continue
			}

			nr.from = string(aBytes)
			nr.to = string(bBytes)
			s.rels = append(s.rels, nr)
		}
	}

}

func (s *spdxDoc) parseTool() {
	s.tools = []Tool{}

	if s.doc.CreationInfo == nil {
		return
	}

	//https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field
	//spdx2.3 spec says If the SPDX document was created using a software tool,
	//indicate the name and version for that tool
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

		//check if version has atleast one-digit
		//if not, then it is not a version
		for _, r := range version {
			if unicode.IsDigit(r) {
				return name, version
			}
		}

		//This is a bad case
		return inputName, ""
	}

	for _, c := range s.doc.CreationInfo.Creators {
		ctType := strings.ToLower(c.CreatorType)
		if ctType != "tool" {
			continue
		}
		t := tool{}
		t.name, t.version = extractVersion(c.Creator)
		s.tools = append(s.tools, t)
	}
}

func (s *spdxDoc) addToLogs(log string) {
	s.logs = append(s.logs, log)
}

func (s *spdxDoc) requiredFields() bool {
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
	//Identify the current SPDX document which may be referenced in relationships
	//by other files, packages internally and documents externally
	if s.doc.SPDXIdentifier == "" {
		s.addToLogs("spdx doc is missing SPDXIdentifier")
		return false
	}
	//Identify name of this document as designated by creator
	if s.doc.DocumentName == "" {
		s.addToLogs("spdx doc is missing DocumentName")
		return false
	}

	//The URI provides an unambiguous mechanism for other SPDX documents to reference SPDX elements within this SPDX document
	if s.doc.DocumentNamespace == "" {
		s.addToLogs("spdx doc is missing Document Namespace")
		return false
	}

	//Identify who (or what, in the case of a tool) created the SPDX document.
	if len(s.doc.CreationInfo.Creators) == 0 {
		s.addToLogs("spdx doc is missing creators")
		return false
	}

	//Identify when the SPDX document was originally created.
	if s.doc.CreationInfo.Created == "" {
		s.addToLogs("spdx doc is missing created timestamp")
		return false
	}
	return true
}

func (s *spdxDoc) pkgRequiredFields(index int) bool {

	pkg := s.doc.Packages[index]

	if pkg.PackageName == "" {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing name", pkg.PackageSPDXIdentifier, index))
		return false
	}

	if pkg.PackageSPDXIdentifier == "" {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d missing identifier", pkg.PackageName, index))
		return false
	}

	//What is the correct behaviour for NONE and NOASSERTION?
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

func (s *spdxDoc) purls(index int) []purl.PURL {
	urls := []purl.PURL{}
	pkg := s.doc.Packages[index]

	if len(pkg.PackageExternalReferences) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no purls found", pkg.PackageName, index))
		return urls
	}

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

func (s *spdxDoc) cpes(index int) []cpe.CPE {
	urls := []cpe.CPE{}
	pkg := s.doc.Packages[index]
	if len(pkg.PackageExternalReferences) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no cpes found", pkg.PackageName, index))
		return urls
	}

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

func (s *spdxDoc) checksums(index int) []Checksum {
	chks := []Checksum{}
	pkg := s.doc.Packages[index]

	if len(pkg.PackageChecksums) == 0 {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no checksum found", pkg.PackageName, index))
		return chks
	}

	for _, c := range pkg.PackageChecksums {
		ck := checksum{}
		ck.alg = string(c.Algorithm)
		ck.content = c.Value
		chks = append(chks, ck)
	}

	return chks
}

func (s *spdxDoc) licenses(index int) []licenses.License {
	lics := []licenses.License{}

	pkg := s.doc.Packages[index]

	otherLicenses := lo.Map(s.doc.OtherLicenses, func(l *v2_3.OtherLicense, _ int) licenses.License {
		return licenses.CreateCustomLicense(l.LicenseIdentifier, l.LicenseName)
	})

	if pkg.PackageLicenseConcluded != "" && strings.ToLower(pkg.PackageLicenseConcluded) != "noassertion" && strings.ToLower(pkg.PackageLicenseConcluded) != "none" {
		conLics := licenses.LookupExpression(pkg.PackageLicenseConcluded, otherLicenses)
		lics = append(lics, conLics...)
		if len(conLics) > 0 {
			return lics
		}
	}

	if pkg.PackageLicenseDeclared != "" && strings.ToLower(pkg.PackageLicenseDeclared) != "noassertion" && strings.ToLower(pkg.PackageLicenseDeclared) != "none" {
		decLics := licenses.LookupExpression(pkg.PackageLicenseDeclared, otherLicenses)
		lics = append(lics, decLics...)
		return lics
	}

	return lics
}

func (s *spdxDoc) getManufacturer(index int) *manufacturer {
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

	return &manufacturer{
		name:  entity.name,
		email: entity.email,
	}
}

func (s *spdxDoc) getSupplier(index int) *supplier {
	pkg := s.doc.Packages[index]

	if pkg.PackageSupplier == nil {
		return nil
	}

	if strings.ToLower(pkg.PackageSupplier.Supplier) == "noassertion" {
		return nil
	}

	entity := parseEntity(fmt.Sprintf("%s: %s", pkg.PackageSupplier.SupplierType, pkg.PackageSupplier.Supplier))
	if entity == nil {
		return nil
	}

	return &supplier{
		name:  entity.name,
		email: entity.email,
	}
}

// https://github.com/spdx/ntia-conformance-checker/issues/100
// Add spdx support to check both supplier and originator
func (s *spdxDoc) addSupplierName(index int) string {
	supplier := s.getSupplier(index)
	manufacturer := s.getManufacturer(index)

	if supplier == nil && manufacturer == nil {
		s.addToLogs(fmt.Sprintf("spdx doc pkg %s at index %d no supplier/originator found", s.doc.Packages[index].PackageName, index))
		return ""
	}

	if supplier != nil {
		return supplier.name
	}

	if manufacturer != nil {
		return manufacturer.name
	}

	return ""
}

func (s *spdxDoc) parsePrimaryComponent() {
	pkgIds := make(map[string]*v2_3.Package)

	for _, pkg := range s.doc.Packages {
		pkgIds[string(pkg.PackageSPDXIdentifier)] = pkg
	}

	for _, r := range s.doc.Relationships {
		if strings.ToUpper(r.Relationship) == spdx_common.TypeRelationshipDescribe {
			_, ok := pkgIds[string(r.RefB.ElementRefID)]
			if ok {
				s.primaryComponentId = string(r.RefB.ElementRefID)
				s.primaryComponent = true
				return
			}
		}
	}
}

type entity struct {
	name  string
	email string
}

func parseEntity(input string) *entity {
	if strings.TrimSpace(input) == "" {
		return nil
	}

	// Regex pattern to match organization or person and email
	pattern := `(Organization|Person)\s*:\s*([^(]+)\s*(?:\(\s*([^)]+)\s*\))?`
	regex := regexp.MustCompile(pattern)
	match := regex.FindStringSubmatch(input)
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
