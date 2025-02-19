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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/swhid"
	"github.com/interlynk-io/sbomqs/pkg/swid"
	"github.com/samber/lo"
)

var (
	cdxSpecVersions   = []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}
	cdxFileFormats    = []string{"json", "xml"}
	cdxPrimaryPurpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "file"}
)

type CdxDoc struct {
	doc              *cydx.BOM
	format           FileFormat
	ctx              context.Context
	CdxSpec          *Specs
	Comps            []GetComponent
	CdxAuthors       []GetAuthor
	CdxTools         []GetTool
	rels             []GetRelation
	logs             []string
	Lifecycle        []string
	CdxSupplier      GetSupplier
	CdxManufacturer  GetManufacturer
	compositions     map[string]string
	PrimaryComponent PrimaryComp
	Dependencies     map[string][]string
	composition      map[string]string
	Vuln             []GetVulnerabilities
	SignatureDetail  GetSignature
}

func newCDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat, sig Signature) (Document, error) {
	var err error

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	var bom *cydx.BOM

	switch format {
	case FileFormatJSON:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	case FileFormatXML:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(f, cydx.BOMFileFormatXML)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	default:
		err = fmt.Errorf("unsupported cdx file format: %s", string(format))
	}

	doc := &CdxDoc{
		doc:             bom,
		format:          format,
		ctx:             ctx,
		SignatureDetail: &sig,
	}
	doc.parse()

	return doc, err
}

func (c CdxDoc) PrimaryComp() GetPrimaryComp {
	return &c.PrimaryComponent
}

func (c CdxDoc) Spec() Spec {
	return *c.CdxSpec
}

func (c CdxDoc) Components() []GetComponent {
	return c.Comps
}

func (c CdxDoc) Authors() []GetAuthor {
	return c.CdxAuthors
}

func (c CdxDoc) Tools() []GetTool {
	return c.CdxTools
}

func (c CdxDoc) Relations() []GetRelation {
	return c.rels
}

func (c CdxDoc) Logs() []string {
	return c.logs
}

func (c CdxDoc) Lifecycles() []string {
	return c.Lifecycle
}

func (c CdxDoc) Supplier() GetSupplier {
	return c.CdxSupplier
}

func (c CdxDoc) Manufacturer() GetManufacturer {
	return c.CdxManufacturer
}

func (c CdxDoc) GetRelationships(componentID string) []string {
	return c.Dependencies[componentID]
}

func (c CdxDoc) GetComposition(componentID string) string {
	return c.composition[componentID]
}

func (c CdxDoc) Vulnerabilities() []GetVulnerabilities {
	return c.Vuln
}

func (c CdxDoc) Signature() GetSignature {
	return c.SignatureDetail
}

func (c *CdxDoc) parse() {
	c.parseDoc()
	c.parseSpec()
	c.parseAuthors()
	c.parseSupplier()
	c.parseManufacturer()
	c.parseTool()
	c.parseCompositions()
	c.parsePrimaryCompAndRelationships()
	c.parseVulnerabilities()
	if c.Signature().GetSigValue() == "" && c.Signature().GetPublicKey() == "" {
		c.addToLogs("extract public key and signature from cylonedx sbom itself")
		c.parseSignature()
	}
	c.parseComps()
}

func (c *CdxDoc) addToLogs(log string) {
	c.logs = append(c.logs, log)
}

func (c *CdxDoc) parseDoc() {
	if c.doc == nil {
		c.addToLogs("cdx doc is not parsable")
		return
	}

	if c.doc.Metadata == nil {
		c.addToLogs("cdx doc is missing metadata")
		return
	}

	if c.doc.Metadata.Lifecycles == nil {
		c.addToLogs("cdx doc is missing lifecycles")
		return
	}

	c.Lifecycle = lo.Map(lo.FromPtr(c.doc.Metadata.Lifecycles), func(l cydx.Lifecycle, _ int) string {
		if l.Phase != "" {
			return string(l.Phase)
		}

		if l.Name != "" {
			return l.Name
		}

		return ""
	})
}

func (c *CdxDoc) parseSpec() {
	sp := NewSpec()
	sp.Format = string(c.format)
	sp.Version = c.doc.SpecVersion.String()
	sp.Name = string(SBOMSpecCDX)
	sp.isReqFieldsPresent = c.requiredFields()

	if c.doc.Metadata != nil {
		sp.CreationTimestamp = c.doc.Metadata.Timestamp
		if c.doc.Metadata.Licenses != nil {
			sp.Licenses = aggregateLicenses(*c.doc.Metadata.Licenses, "")
		}
	}
	sp.Namespace = c.doc.SerialNumber
	sp.SpecType = string(SBOMSpecCDX)

	if c.doc.SerialNumber != "" && strings.HasPrefix(sp.Namespace, "urn:uuid:") {
		sp.URI = fmt.Sprintf("%s/%d", c.doc.SerialNumber, c.doc.Version)
	}

	if c.doc.ExternalReferences != nil {
		for _, extRefs := range *c.doc.ExternalReferences {
			if extRefs.Type == "bom" {
				sp.ExternalDocReference = append(sp.ExternalDocReference, extRefs.URL)
			}
		}
	}

	c.CdxSpec = sp
}

func (c *CdxDoc) parseVulnerabilities() {
	if c.doc.Vulnerabilities != nil {
		for _, v := range *c.doc.Vulnerabilities {
			if v.ID != "" {
				vuln := Vulnerability{}
				vuln.ID = v.ID
				c.Vuln = append(c.Vuln, vuln)
			}
		}
	}
}

// until and unless cyclondx-go library supports signature, this part is useless
// So, we are using tech hack to parse signature directly from JSON sbom file
func (c *CdxDoc) parseSignature() {
	log := logger.FromContext(c.ctx)
	log.Debug("parseSignature()")
	c.SignatureDetail = &Signature{}
	if c.doc.Declarations != nil {
		if c.doc.Declarations.Signature != nil {
			sigValue := c.doc.Declarations.Signature.Value
			pubKeyModulus := c.doc.Declarations.Signature.PublicKey.N
			pubKeyExponent := c.doc.Declarations.Signature.PublicKey.E

			// decode the signature
			signatureValue, err := base64.StdEncoding.DecodeString(sigValue)
			if err != nil {
				log.Debug("Error decoding signature:", err)
				return
			}

			// write the signature to a file
			if err := os.WriteFile("extracted_signature.bin", signatureValue, 0o600); err != nil {
				log.Debug("Error writing signature to file: %s", err)
				return
			}
			c.addToLogs("Signature written to file: extracted_signature.bin")

			// extract the public key modulus and exponent
			modulus, err := base64.StdEncoding.DecodeString(pubKeyModulus)
			if err != nil {
				log.Debug("Error decoding public key modulus:", err)
				return
			}

			exponent := decodeBase64URLEncodingToInt(pubKeyExponent)
			if exponent == 0 {
				c.addToLogs("Invalid public key exponent.")
				return
			}

			// create the RSA public key
			pubKey := &rsa.PublicKey{
				N: decodeBigInt(modulus),
				E: exponent,
			}

			// write the public key to a PEM file
			pubKeyPEM := publicKeyToPEM(pubKey)
			if err := os.WriteFile("extracted_public_key.pem", pubKeyPEM, 0o600); err != nil {
				log.Debug("Error writing public key to file:", err)
				return
			}

			sig := Signature{}
			sig.PublicKey = string(pubKeyPEM)
			sig.SigValue = string(signatureValue)

			c.SignatureDetail = &sig

			c.addToLogs("Public key written to file: extracted_public_key.pem")
		}
	}
}

func decodeBase64URLEncodingToInt(input string) int {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return 0
	}
	if len(bytes) == 0 {
		return 0
	}
	result := 0
	for _, b := range bytes {
		result = result<<8 + int(b)
	}
	return result
}

func decodeBigInt(input []byte) *big.Int {
	result := new(big.Int)
	result.SetBytes(input)
	return result
}

func publicKeyToPEM(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return nil
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubPEM
}

func (c *CdxDoc) requiredFields() bool {
	if c.doc == nil {
		c.addToLogs("cdx doc is not parsable")
		return false
	}

	// This field is only required for JSON not for XML.
	if c.format == FileFormatJSON && c.doc.BOMFormat == "" {
		c.addToLogs("cdx doc is missing BOMFormat")
		return false
	}

	if c.doc.SpecVersion.String() == "" {
		c.addToLogs("cdx doc is missing specVersion")
		return false
	}

	if c.doc.Version < 1 {
		c.addToLogs("cdx doc is missing doc version")
		return false
	}

	if c.doc.Dependencies != nil {
		deps := lo.CountBy(lo.FromPtr(c.doc.Dependencies), func(d cydx.Dependency) bool {
			return d.Ref == ""
		})

		if deps > 0 {
			c.addToLogs("cdx doc is missing dependencies")
			return false
		}
	}
	return true
}

func copyC(cdxc *cydx.Component, c *CdxDoc) *Component {
	if cdxc == nil {
		return nil
	}

	nc := NewComponent()
	nc.Version = cdxc.Version
	nc.Name = cdxc.Name
	nc.purpose = string(cdxc.Type)
	nc.isReqFieldsPresent = c.pkgRequiredFields(cdxc)
	nc.CopyRight = cdxc.Copyright
	ncpe := cpe.NewCPE(cdxc.CPE)
	if ncpe.Valid() {
		nc.Cpes = []cpe.CPE{ncpe}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid cpes found", cdxc.Name, -1))
	}

	npurl := purl.NewPURL(cdxc.PackageURL)
	if npurl.Valid() {
		nc.Purls = []purl.PURL{npurl}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid purl found", cdxc.Name, -1))
	}

	if cdxc.SWHID != nil {
		for _, swhidStr := range *cdxc.SWHID {
			nswhid := swhid.NewSWHID(swhidStr)
			if nswhid.Valid() {
				nc.Swhid = append(nc.Swhid, nswhid)
			} else {
				c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid swhid found", cdxc.Name, -1))
			}
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil SWHID", cdxc.Name))
	}

	if cdxc.SWID != nil {
		nswid := swid.NewSWID(cdxc.SWID.TagID, cdxc.SWID.Name)
		if nswid.Valid() {
			nc.Swid = []swid.SWID{nswid}
		} else {
			c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid swid found", cdxc.Name, -1))
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil SWID or SWID.Name", cdxc.Name))
	}

	if cdxc.OmniborID != nil {
		for _, omniStr := range *cdxc.OmniborID {
			omniID := omniborid.NewOmni(omniStr)
			if omniID.Valid() {
				nc.OmniID = append(nc.OmniID, omniID)
			} else {
				c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid omniborid found", cdxc.Name, -1))
			}
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil OmniborID", cdxc.Name))
	}

	nc.Checksums = c.checksums(cdxc)
	nc.licenses = c.licenses(cdxc)
	nc.declaredLicense = c.declaredLicenses(cdxc)
	nc.concludedLicense = c.concludedLicenses(cdxc)

	supplier := c.assignSupplier(cdxc)
	if supplier != nil {
		nc.Supplier = *supplier
	}

	if cdxc.ExternalReferences != nil {
		sources := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeVCS
		})

		if len(sources) > 0 {
			nc.sourceCodeURL = sources[0].URL
		}

		downloads := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeDistribution || er.Type == cydx.ERTypeDistributionIntake
		})

		if len(downloads) > 0 {
			nc.DownloadLocation = downloads[0].URL
		}
	}

	if cdxc.Name == c.PrimaryComponent.Name {
		nc.PrimaryCompt = c.PrimaryComponent
	}
	nc.ID = cdxc.BOMRef

	// license->acknowlegement(1.6+): currently acknowlegement field doesn't support
	nc.declaredLicense = nil
	nc.concludedLicense = nil

	return nc
}

func (c *CdxDoc) parseComps() {
	c.Comps = []GetComponent{}
	comps := map[string]*Component{}
	if c.doc.Metadata != nil && c.doc.Metadata.Component != nil {
		walkComponents(&[]cydx.Component{*c.doc.Metadata.Component}, c, comps)
	}

	if c.doc.Components != nil {
		walkComponents(c.doc.Components, c, comps)
	}

	for _, v := range comps {
		c.Comps = append(c.Comps, v)
	}
}

func walkComponents(comps *[]cydx.Component, doc *CdxDoc, store map[string]*Component) {
	if comps == nil {
		return
	}
	for _, c := range *comps {
		if c.Components != nil {
			walkComponents(c.Components, doc, store)
		}
		//nolint:gosec
		if _, ok := store[compID(&c)]; ok {
			// already present no need to re add it.
			continue
		}
		//nolint:gosec
		store[compID(&c)] = copyC(&c, doc)
	}
}

func compID(comp *cydx.Component) string {
	if comp.BOMRef != "" {
		return comp.BOMRef
	}

	if comp.PackageURL != "" {
		return comp.PackageURL
	}

	// A component with no BOMREF or PackageURL is a bad component, so we generate a UUID for it.
	// This is a temporary solution until we can figure out how to handle this case.
	id := uuid.New()
	return id.String()
}

func (c *CdxDoc) pkgRequiredFields(comp *cydx.Component) bool {
	if string(comp.Type) == "" {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s missing type field", comp.Name))
		return false
	}

	if comp.Name == "" {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s missing type field", comp.BOMRef))
		return false
	}

	return true
}

func (c *CdxDoc) checksums(comp *cydx.Component) []GetChecksum {
	chks := []GetChecksum{}

	if len(lo.FromPtr(comp.Hashes)) == 0 {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no checksum found", comp.Name))
		return chks
	}

	for _, cl := range lo.FromPtr(comp.Hashes) {
		ck := Checksum{}
		ck.Alg = string(cl.Algorithm)
		ck.Content = cl.Value
		chks = append(chks, ck)
	}
	return chks
}

func (c *CdxDoc) licenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "")
}

func (c *CdxDoc) declaredLicenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "declared")
}

func (c *CdxDoc) concludedLicenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "concluded")
}

func aggregateLicenses(clicenses cydx.Licenses, filter string) []licenses.License {
	if clicenses == nil {
		return []licenses.License{}
	}

	lics := []licenses.License{}

	getLicenses := func(exp string) []licenses.License {
		return licenses.LookupExpression(exp, []licenses.License{})
	}

	for _, cl := range clicenses {
		if filter == "" && cl.Expression != "" {
			lics = append(lics, getLicenses(cl.Expression)...)
		} else if cl.License != nil {
			if filter == "" || string(cl.License.Acknowledgement) == filter {
				if cl.License.ID != "" {
					lics = append(lics, getLicenses(cl.License.ID)...)
				} else if cl.License.Name != "" {
					lics = append(lics, getLicenses(cl.License.Name)...)
				}
			}
		}
	}

	return lics
}

func (c *CdxDoc) parseTool() {
	c.CdxTools = []GetTool{}

	if c.doc.Metadata == nil {
		return
	}

	if c.doc.Metadata.Tools == nil {
		return
	}

	for _, tt := range lo.FromPtr(c.doc.Metadata.Tools.Tools) {
		t := Tool{}
		t.Name = tt.Name
		t.Version = tt.Version
		c.CdxTools = append(c.CdxTools, t)
	}

	for _, ct := range lo.FromPtr(c.doc.Metadata.Tools.Components) {
		t := Tool{}
		t.Name = ct.Name
		t.Version = ct.Version
		c.CdxTools = append(c.CdxTools, t)
	}

	for _, ct := range lo.FromPtr(c.doc.Metadata.Tools.Services) {
		t := Tool{}
		t.Name = ct.Name
		t.Version = ct.Version
		c.CdxTools = append(c.CdxTools, t)
	}
}

func (c *CdxDoc) parseAuthors() {
	c.CdxAuthors = []GetAuthor{}

	if c.doc.Metadata == nil {
		return
	}

	for _, auth := range lo.FromPtr(c.doc.Metadata.Authors) {
		a := Author{}
		a.Name = auth.Name
		a.Email = auth.Email
		a.Phone = auth.Phone
		a.AuthorType = "person"
		c.CdxAuthors = append(c.CdxAuthors, a)
	}
}

func (c *CdxDoc) parseSupplier() {
	// Early return if required nested fields are nil
	if c.doc.Metadata == nil || c.doc.Metadata.Supplier == nil {
		return
	}

	// Initialize supplier with known fields
	supplier := Supplier{
		Name: c.doc.Metadata.Supplier.Name,
	}

	// Safely handle URL
	if urls := lo.FromPtr(c.doc.Metadata.Supplier.URL); len(urls) > 0 {
		supplier.URL = urls[0]
	}

	// Handle contacts array
	if c.doc.Metadata.Supplier.Contact != nil {
		contacts := lo.FromPtr(c.doc.Metadata.Supplier.Contact)
		if len(contacts) > 0 {
			// Pre-allocate contacts slice with known capacity
			supplier.Contacts = make([]Contact, 0, len(contacts))

			// Process each contact
			for _, cydxContact := range contacts {
				supplier.Contacts = append(supplier.Contacts, Contact{
					Name:  cydxContact.Name,
					Email: cydxContact.Email,
				})
			}
		}
	}

	c.CdxSupplier = supplier
}

func (c *CdxDoc) parseManufacturer() {
	if c.doc.Metadata == nil || c.doc.Metadata.Manufacture == nil {
		return
	}

	manufacturer := Manufacturer{Name: c.doc.Metadata.Manufacture.Name}

	if urls := lo.FromPtr(c.doc.Metadata.Manufacture.URL); len(urls) > 0 {
		manufacturer.URL = urls[0]
	}

	contacts := lo.FromPtr(c.doc.Metadata.Manufacture.Contact)
	if len(contacts) > 0 {
		manufacturer.Contacts = make([]Contact, len(contacts))
		for i, contact := range contacts {
			manufacturer.Contacts[i] = Contact{
				Name:  contact.Name,
				Email: contact.Email,
			}
		}
	}

	c.CdxManufacturer = manufacturer
}

func (c *CdxDoc) parsePrimaryCompAndRelationships() {
	if c.doc.Metadata == nil {
		return
	}
	if c.doc.Metadata.Component == nil {
		return
	}

	c.Dependencies = make(map[string][]string)

	c.PrimaryComponent.Present = true
	c.PrimaryComponent.ID = c.doc.Metadata.Component.BOMRef
	c.PrimaryComponent.Name = c.doc.Metadata.Component.Name
	var totalDependencies int

	c.rels = []GetRelation{}

	for _, r := range lo.FromPtr(c.doc.Dependencies) {
		for _, d := range lo.FromPtr(r.Dependencies) {
			nr := Relation{}
			nr.From = r.Ref
			nr.To = d
			if r.Ref == c.PrimaryComponent.ID {
				c.PrimaryComponent.HasDependency = true
				c.PrimaryComponent.AllDependencies = append(c.PrimaryComponent.AllDependencies, d)
				totalDependencies++
				c.rels = append(c.rels, nr)
				c.Dependencies[c.PrimaryComponent.ID] = append(c.Dependencies[c.PrimaryComponent.ID], d)
			} else {
				c.rels = append(c.rels, nr)
				c.Dependencies[r.Ref] = append(c.Dependencies[r.Ref], d)
			}
		}
	}
	c.PrimaryComponent.Dependecies = totalDependencies
}

func (c *CdxDoc) assignSupplier(comp *cydx.Component) *Supplier {
	if comp.Supplier == nil {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no supplier found", comp.Name))
		return nil
	}

	supplier := Supplier{Name: comp.Supplier.Name}

	if urls := lo.FromPtr(comp.Supplier.URL); len(urls) > 0 {
		supplier.URL = urls[0]
	}

	contacts := lo.FromPtr(comp.Supplier.Contact)
	if len(contacts) > 0 {
		supplier.Contacts = make([]Contact, len(contacts))
		for i, contact := range contacts {
			supplier.Contacts[i] = Contact{
				Name:  contact.Name,
				Email: contact.Email,
			}
		}
	}

	return &supplier
}

func (c *CdxDoc) parseCompositions() {
	c.compositions = make(map[string]string)

	if c.doc.Compositions == nil {
		return
	}

	for _, composition := range lo.FromPtr(c.doc.Compositions) {
		assemblies := lo.FromPtr(composition.Assemblies)
		if len(assemblies) == 0 {
			continue
		}

		for _, assembly := range assemblies {
			c.compositions[string(assembly)] = string(composition.Aggregate)
		}
	}
}
