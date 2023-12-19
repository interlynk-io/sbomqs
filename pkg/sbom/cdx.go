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
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/samber/lo"
)

var cdx_spec_versions = []string{"1.0", "1.1", "1.2", "1.3", "1.4"}
var cdx_file_formats = []string{"json", "xml"}
var cdx_primary_purpose = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "file"}

type cdxDoc struct {
	doc     *cydx.BOM
	format  FileFormat
	ctx     context.Context
	spec    *spec
	comps   []Component
	authors []Author
	tools   []Tool
	rels    []Relation
	logs    []string
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

func (c cdxDoc) Components() []Component {
	return c.comps
}

func (c cdxDoc) Authors() []Author {
	return c.authors
}

func (c cdxDoc) Tools() []Tool {
	return c.tools
}

func (c cdxDoc) Relations() []Relation {
	return c.rels
}
func (c cdxDoc) Logs() []string {
	return c.logs
}

func (c *cdxDoc) parse() {
	c.parseSpec()
	c.parseComps()
	c.parseAuthors()
	c.parseTool()
	c.parseRels()
}

func (c *cdxDoc) addToLogs(log string) {
	c.logs = append(c.logs, log)
}

func (c *cdxDoc) parseSpec() {
	sp := newSpec()
	sp.format = string(c.format)
	sp.version = c.doc.SpecVersion.String()
	sp.name = string(SBOMSpecCDX)
	sp.isReqFieldsPresent = c.requiredFields()

	addLicense := func(agg *[]License, n []license) {
		for _, l := range n {
			*agg = append(*agg, l)
		}
	}

	if c.doc.Metadata != nil {
		sp.creationTimestamp = c.doc.Metadata.Timestamp

		lics := []License{}
		for _, l := range lo.FromPtr(c.doc.Metadata.Licenses) {
			if l.Expression != "" {
				addLicense(&lics, newLicenseFromID(l.Expression))
			} else if l.License != nil {
				addLicense(&lics, newLicenseFromID(l.License.ID))
			}
		}

		sp.licenses = lics
	}

	sp.namespace = c.doc.SerialNumber
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

func copyC(cdxc *cydx.Component, c *cdxDoc) *component {
	if cdxc == nil {
		return nil
	}

	nc := newComponent()
	nc.version = cdxc.Version
	nc.name = cdxc.Name
	nc.supplierName = c.addSupplierName(cdxc)
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
	nc.checksums = c.checksums(cdxc)
	nc.licenses = c.licenses(cdxc)
	nc.id = cdxc.BOMRef

	return nc
}

func (c *cdxDoc) parseComps() {
	c.comps = []Component{}
	comps := map[string]*component{}
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

func walkComponents(comps *[]cydx.Component, doc *cdxDoc, store map[string]*component) {
	if comps == nil {
		return
	}
	for _, c := range *comps {
		if c.Components != nil {
			walkComponents(c.Components, doc, store)
		}
		if _, ok := store[compID(&c)]; ok {
			//already present no need to re add it.
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

func (c *cdxDoc) checksums(comp *cydx.Component) []Checksum {
	chks := []Checksum{}

	if len(lo.FromPtr(comp.Hashes)) == 0 {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no checksum found", comp.Name))
		return chks
	}

	for _, cl := range lo.FromPtr(comp.Hashes) {
		ck := checksum{}
		ck.alg = string(cl.Algorithm)
		ck.content = cl.Value
		chks = append(chks, ck)
	}
	return chks
}

func (c *cdxDoc) licenses(comp *cydx.Component) []License {
	lics := []License{}

	addLicense := func(agg *[]License, n []license) {
		for _, l := range n {
			*agg = append(*agg, l)
		}
	}

	for _, cl := range lo.FromPtr(comp.Licenses) {
		if cl.Expression != "" {
			addLicense(&lics, newLicenseFromID(cl.Expression))
		} else if cl.License != nil {
			addLicense(&lics, newLicenseFromID(cl.License.ID))
		}
	}

	// Remove the empty if statement
	// if comp.Evidence != nil {

	// }

	removeDups := func(lics []License) []License {
		uniqs := []License{}
		dedup := map[string]bool{}
		for _, l := range lics {
			if _, ok := dedup[l.Short()]; !ok {
				uniqs = append(uniqs, l)
				dedup[l.Short()] = true
			}
		}
		return uniqs

	}
	finalLics := removeDups(lics)
	if len(finalLics) == 0 {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no licenses found", comp.Name))
	}

	return finalLics
}

func (c *cdxDoc) parseTool() {
	c.tools = []Tool{}

	if c.doc.Metadata == nil {
		return
	}

	for _, tt := range lo.FromPtr(c.doc.Metadata.Tools.Tools) {
		t := tool{}
		t.name = tt.Name
		t.version = tt.Version
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
		a.authorType = "person"
		c.authors = append(c.authors, a)
	}
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
func (c *cdxDoc) addSupplierName(comp *cydx.Component) string {
	if comp.Supplier == nil {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no supplier found", comp.Name))
		return ""
	}

	name := strings.ToLower(comp.Supplier.Name)

	if name == "" {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no supplier found", comp.Name))
		return ""
	}
	return name
}
