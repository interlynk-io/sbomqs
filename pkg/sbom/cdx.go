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
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/samber/lo"
)

var (
	cdx_spec_versions   = []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}
	cdx_file_formats    = []string{"json", "xml"}
	cdx_primary_purpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "file"}
)

type cdxDoc struct {
	doc                *cydx.BOM
	format             FileFormat
	ctx                context.Context
	spec               *Specs
	comps              []GetComponent
	authors            []Author
	tools              []GetTool
	rels               []Relation
	logs               []string
	primaryComponent   bool
	lifecycles         []string
	supplier           GetSupplier
	manufacturer       Manufacturer
	primaryComponentId string
	compositions       map[string]string
}

func newCDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat) (Document, error) {
	f.Seek(0, io.SeekStart)

	var err error
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

	doc := &cdxDoc{
		doc:    bom,
		format: format,
		ctx:    ctx,
	}
	doc.parse()

	return doc, err
}

func (c cdxDoc) Spec() Spec {
	return *c.spec
}

func (c cdxDoc) Components() []GetComponent {
	return c.comps
}

func (c cdxDoc) Authors() []Author {
	return c.authors
}

func (c cdxDoc) Tools() []GetTool {
	return c.tools
}

func (c cdxDoc) Relations() []Relation {
	return c.rels
}

func (c cdxDoc) Logs() []string {
	return c.logs
}

func (c cdxDoc) PrimaryComponent() bool {
	return c.primaryComponent
}

func (c cdxDoc) Lifecycles() []string {
	return c.lifecycles
}

func (c cdxDoc) Supplier() GetSupplier {
	return c.supplier
}

func (c cdxDoc) Manufacturer() Manufacturer {
	return c.manufacturer
}

func (c *cdxDoc) parse() {
	c.parseDoc()
	c.parseSpec()
	c.parseAuthors()
	c.parseSupplier()
	c.parseManufacturer()
	c.parseTool()
	c.parsePrimaryComponent()
	c.parseCompositions()
	c.parseRels()
	c.parseComps()
}

func (c *cdxDoc) addToLogs(log string) {
	c.logs = append(c.logs, log)
}

func (c *cdxDoc) parseDoc() {
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

	c.lifecycles = lo.Map(lo.FromPtr(c.doc.Metadata.Lifecycles), func(l cydx.Lifecycle, _ int) string {
		if l.Phase != "" {
			return string(l.Phase)
		}

		if l.Name != "" {
			return string(l.Name)
		}

		return ""
	})
}

func (c *cdxDoc) parseSpec() {
	sp := NewSpec()
	sp.Format = string(c.format)
	sp.Version = c.doc.SpecVersion.String()
	sp.Name = string(SBOMSpecCDX)
	sp.isReqFieldsPresent = c.requiredFields()

	if c.doc.Metadata != nil {
		sp.CreationTimestamp = c.doc.Metadata.Timestamp
		if c.doc.Metadata.Licenses != nil {
			sp.Licenses = aggregate_licenses(*c.doc.Metadata.Licenses)
		}
	}
	sp.Namespace = c.doc.SerialNumber
	sp.SpecType = string(SBOMSpecCDX)

	if c.doc.SerialNumber != "" && strings.HasPrefix(sp.Namespace, "urn:uuid:") {
		sp.uri = fmt.Sprintf("%s/%d", c.doc.SerialNumber, c.doc.Version)
	}

	c.spec = sp
}

func (c *cdxDoc) requiredFields() bool {
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
			return string(d.Ref) == ""
		})

		if deps > 0 {
			c.addToLogs("cdx doc is missing depedencies")
			return false
		}
	}
	return true
}

func copyC(cdxc *cydx.Component, c *cdxDoc) *Component {
	if cdxc == nil {
		return nil
	}

	nc := NewComponent()
	nc.Version = cdxc.Version
	nc.Name = cdxc.Name
	nc.purpose = string(cdxc.Type)
	nc.isReqFieldsPresent = c.pkgRequiredFields(cdxc)

	ncpe := cpe.NewCPE(cdxc.CPE)
	if ncpe.Valid() {
		nc.cpes = []cpe.CPE{ncpe}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid cpes found", cdxc.Name, -1))
	}

	npurl := purl.NewPURL(cdxc.PackageURL)
	if npurl.Valid() {
		nc.purls = []purl.PURL{npurl}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid purl found", cdxc.Name, -1))
	}

	nc.Checksums = c.checksums(cdxc)
	nc.licenses = c.licenses(cdxc)

	supplier := c.assignSupplier(cdxc)
	if supplier != nil {
		nc.Supplier = *supplier
		nc.SupplierName = supplier.Name
	}

	if cdxc.ExternalReferences != nil {
		sources := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeVCS
		})

		if len(sources) > 0 {
			nc.sourceCodeUrl = sources[0].URL
		}

		downloads := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeDistribution || er.Type == cydx.ERTypeDistributionIntake
		})

		if len(downloads) > 0 {
			nc.DownloadLocation = downloads[0].URL
		}
	}

	if cdxc.BOMRef == c.primaryComponentId {
		nc.isPrimary = true
	}

	fromRelsPresent := func(rels []Relation, compID string) bool {
		for _, r := range rels {
			if r.From() == compID {
				return true
			}
		}
		return false
	}

	compNormalise := func(compID string) string {
		switch cydx.CompositionAggregate(compID) {
		case cydx.CompositionAggregateComplete:
			return "complete"
		case cydx.CompositionAggregateIncomplete:
			return "incomplete"
		case cydx.CompositionAggregateIncompleteFirstPartyOnly:
			return "incomplete-first-party-only"
		case cydx.CompositionAggregateIncompleteFirstPartyOpenSourceOnly:
			return "incomplete-first-party-open-source-only"
		case cydx.CompositionAggregateIncompleteFirstPartyProprietaryOnly:
			return "incomplete-first-party-proprietary-only"
		case cydx.CompositionAggregateIncompleteThirdPartyOnly:
			return "incomplete-third-party-only"
		case cydx.CompositionAggregateIncompleteThirdPartyOpenSourceOnly:
			return "incomplete-third-party-open-source-only"
		case cydx.CompositionAggregateIncompleteThirdPartyProprietaryOnly:
			return "incomplete-third-party-proprietary-only"
		case cydx.CompositionAggregateNotSpecified:
			return "not-specified"
		case cydx.CompositionAggregateUnknown:
			return "unknown"
		}

		return "not-specified"
	}

	nc.hasRelationships = fromRelsPresent(c.rels, cdxc.BOMRef)
	if c.compositions != nil {
		if comp, ok := c.compositions[cdxc.BOMRef]; ok {
			nc.relationshipState = compNormalise(comp)
		}
	}

	nc.Id = cdxc.BOMRef
	return nc
}

func (c *cdxDoc) parseComps() {
	c.comps = []GetComponent{}
	comps := map[string]*Component{}
	if c.doc.Metadata != nil && c.doc.Metadata.Component != nil {
		walkComponents(&[]cydx.Component{*c.doc.Metadata.Component}, c, comps)
	}

	if c.doc.Components != nil {
		walkComponents(c.doc.Components, c, comps)
	}

	for _, v := range comps {
		c.comps = append(c.comps, v)
	}
}

func walkComponents(comps *[]cydx.Component, doc *cdxDoc, store map[string]*Component) {
	if comps == nil {
		return
	}
	for _, c := range *comps {
		if c.Components != nil {
			walkComponents(c.Components, doc, store)
		}
		if _, ok := store[compID(&c)]; ok {
			// already present no need to re add it.
			continue
		}
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

func (c *cdxDoc) pkgRequiredFields(comp *cydx.Component) bool {
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

func (c *cdxDoc) checksums(comp *cydx.Component) []GetChecksum {
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

func (c *cdxDoc) licenses(comp *cydx.Component) []licenses.License {
	return aggregate_licenses(lo.FromPtr(comp.Licenses))
}

func aggregate_licenses(clicenses cydx.Licenses) []licenses.License {
	if clicenses == nil {
		return []licenses.License{}
	}

	lics := []licenses.License{}

	getLicenses := func(exp string) []licenses.License {
		return licenses.LookupExpression(exp, []licenses.License{})
	}

	for _, cl := range clicenses {
		if cl.Expression != "" {
			lics = append(lics, getLicenses(cl.Expression)...)
		} else if cl.License != nil {
			if cl.License.ID != "" {
				lics = append(lics, getLicenses(cl.License.ID)...)
			} else if cl.License.Name != "" {
				lics = append(lics, getLicenses(cl.License.Name)...)
			}
		}
	}
	return lics
}

func (c *cdxDoc) parseTool() {
	c.tools = []GetTool{}

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
		c.tools = append(c.tools, t)
	}

	for _, ct := range lo.FromPtr(c.doc.Metadata.Tools.Components) {
		t := Tool{}
		t.Name = ct.Name
		t.Version = ct.Version
		c.tools = append(c.tools, t)
	}
}

func (c *cdxDoc) parseAuthors() {
	c.authors = []Author{}

	if c.doc.Metadata == nil {
		return
	}

	for _, auth := range lo.FromPtr(c.doc.Metadata.Authors) {
		a := author{}
		a.name = auth.Name
		a.email = auth.Email
		a.authorType = "person"
		c.authors = append(c.authors, a)
	}
}

func (c *cdxDoc) parseSupplier() {
	if c.doc.Metadata == nil {
		return
	}

	if c.doc.Metadata.Supplier == nil {
		return
	}

	supplier := Supplier{}

	supplier.Name = c.doc.Metadata.Supplier.Name
	supplier.Url = lo.FromPtr(c.doc.Metadata.Supplier.URL)[0]

	if c.doc.Metadata.Supplier.Contact != nil {
		for _, cydxContact := range lo.FromPtr(c.doc.Metadata.Supplier.Contact) {
			ctt := contact{}
			ctt.name = cydxContact.Name
			ctt.email = cydxContact.Email
			supplier.Contacts = append(supplier.Contacts, ctt)
		}
	}

	c.supplier = supplier
}

func (c *cdxDoc) parseManufacturer() {
	if c.doc.Metadata == nil {
		return
	}

	if c.doc.Metadata.Manufacture == nil {
		return
	}

	m := manufacturer{}

	m.name = c.doc.Metadata.Manufacture.Name
	m.url = lo.FromPtr(c.doc.Metadata.Manufacture.URL)[0]

	if c.doc.Metadata.Manufacture.Contact != nil {
		for _, cydxContact := range lo.FromPtr(c.doc.Metadata.Manufacture.Contact) {
			ctt := contact{}
			ctt.name = cydxContact.Name
			ctt.email = cydxContact.Email
			m.contacts = append(m.contacts, ctt)
		}
	}

	c.manufacturer = m
}

func (c *cdxDoc) parseRels() {
	c.rels = []Relation{}

	for _, r := range lo.FromPtr(c.doc.Dependencies) {
		for _, d := range lo.FromPtr(r.Dependencies) {
			nr := relation{}
			nr.from = r.Ref
			nr.to = d
			c.rels = append(c.rels, nr)
		}
	}
}

func (c *cdxDoc) assignSupplier(comp *cydx.Component) *Supplier {
	if comp.Supplier == nil {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no supplier found", comp.Name))
		return nil
	}

	supplier := Supplier{}

	if comp.Supplier.Name != "" {
		supplier.Name = comp.Supplier.Name
	}

	if comp.Supplier.URL != nil && len(lo.FromPtr(comp.Supplier.URL)) > 0 {
		supplier.Url = lo.FromPtr(comp.Supplier.URL)[0]
	}

	if comp.Supplier.Contact != nil {
		for _, cydxContact := range lo.FromPtr(comp.Supplier.Contact) {
			ctt := contact{}
			ctt.name = cydxContact.Name
			ctt.email = cydxContact.Email
			supplier.Contacts = append(supplier.Contacts, ctt)
		}
	}

	return &supplier
}

func (c *cdxDoc) parsePrimaryComponent() {
	if c.doc.Metadata == nil {
		return
	}

	if c.doc.Metadata.Component == nil {
		return
	}

	c.primaryComponent = true
	c.primaryComponentId = c.doc.Metadata.Component.BOMRef
}

func (c *cdxDoc) parseCompositions() {
	if c.doc.Compositions == nil {
		c.compositions = map[string]string{}
		return
	}

	for _, comp := range lo.FromPtr(c.doc.Compositions) {
		if comp.Assemblies == nil {
			continue
		}

		for _, assembly := range lo.FromPtr(comp.Assemblies) {
			c.compositions[string(assembly)] = string(comp.Aggregate)
		}
	}
}
