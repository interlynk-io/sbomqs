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

package policy

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// Extractor provides a simple mapping from canonical field names to
// component-level or document-level.
type Extractor struct {
	Doc         sbom.Document
	compGetters map[string]func(sbom.GetComponent) []string
	docGetters  map[string]func(sbom.Document) []string
}

// NewExtractor creates an Extractor for SBOM fields.
func NewExtractor(doc sbom.Document) *Extractor {
	extractor := &Extractor{
		Doc:         doc,
		compGetters: map[string]func(sbom.GetComponent) []string{},
		docGetters:  map[string]func(sbom.Document) []string{},
	}

	// component-level mappings (canonical keys are lowercase)
	extractor.compGetters["name"] = func(c sbom.GetComponent) []string {
		if s := c.GetName(); s != "" {
			return []string{s}
		}
		return nil
	}

	// alias
	extractor.compGetters["component_name"] = extractor.compGetters["name"]

	extractor.compGetters["version"] = func(c sbom.GetComponent) []string {
		if s := c.GetVersion(); s != "" {
			return []string{s}
		}
		return nil
	}

	extractor.compGetters["license"] = func(c sbom.GetComponent) []string {
		licenses := []string{}
		for _, l := range c.Licenses() {
			if ln := l.Name(); ln != "" {
				licenses = append(licenses, ln)
			}
		}
		return nilOrSlice(licenses)
	}

	extractor.compGetters["purl"] = func(c sbom.GetComponent) []string {
		purls := []string{}
		for _, p := range c.GetPurls() {
			if s := p.String(); s != "" {
				purls = append(purls, s)
			}
		}
		return nilOrSlice(purls)
	}

	extractor.compGetters["cpe"] = func(c sbom.GetComponent) []string {
		cpes := []string{}
		for _, cp := range c.GetCpes() {
			if s := cp.String(); s != "" {
				cpes = append(cpes, s)
			}
		}
		return nilOrSlice(cpes)
	}

	extractor.compGetters["copyright"] = func(c sbom.GetComponent) []string {
		if s := c.GetCopyRight(); s != "" {
			return []string{s}
		}
		return nil
	}

	// keep canonical key lowercase: "downloadlocation" to avoid special chars in lookups
	extractor.compGetters["downloadlocation"] = func(c sbom.GetComponent) []string {
		if s := c.GetDownloadLocationURL(); s != "" {
			return []string{s}
		}
		return nil
	}

	// canonical "type" (primary purpose)
	extractor.compGetters["type"] = func(c sbom.GetComponent) []string {
		if s := c.PrimaryPurpose(); s != "" {
			return []string{s}
		}
		return nil
	}

	// supplier: aggregate common supplier fields
	extractor.compGetters["supplier"] = func(c sbom.GetComponent) []string {
		suppliers := []string{}
		if sup := c.Suppliers(); sup != nil {
			if name := sup.GetName(); name != "" {
				suppliers = append(suppliers, name)
			}
			if em := sup.GetEmail(); em != "" {
				suppliers = append(suppliers, em)
			}
			if u := sup.GetURL(); u != "" {
				suppliers = append(suppliers, u)
			}
		}
		return nilOrSlice(suppliers)
	}

	// ---------------------
	// document-level mappings (require sbom_ prefix in policy)
	// ---------------------

	// sbom_timestamp -> try doc.Spec().Created() or similar
	extractor.docGetters["sbom_timestamp"] = func(d sbom.Document) []string {
		if d == nil {
			return nil
		}
		// assume Spec() returns a type with Created() string
		spec := d.Spec()
		// be defensive: check method presence by calling and guard zero values
		if spec != nil {
			if created := spec.GetCreationTimestamp(); created != "" {
				return []string{created}
			}
		}
		return nil
	}

	// sbom_author -> aggregate d.Authors()
	extractor.docGetters["sbom_author"] = func(d sbom.Document) []string {
		sbomAuthors := []string{}
		for _, a := range d.Authors() {
			if n := a.GetName(); n != "" {
				sbomAuthors = append(sbomAuthors, n)
			}
			if n := a.GetEmail(); n != "" {
				sbomAuthors = append(sbomAuthors, n)
			}

		}
		return nilOrSlice(sbomAuthors)
	}

	// sbom_supplier -> doc-level supplier
	extractor.docGetters["sbom_supplier"] = func(d sbom.Document) []string {
		sbomSuppliers := []string{}
		if s := d.Supplier(); s != nil {
			if name := s.GetName(); name != "" {
				sbomSuppliers = append(sbomSuppliers, name)
			}
			if email := s.GetEmail(); email != "" {
				sbomSuppliers = append(sbomSuppliers, email)
			}

			if url := s.GetURL(); url != "" {
				sbomSuppliers = append(sbomSuppliers, url)
			}
		}
		return nilOrSlice(sbomSuppliers)
	}

	// sbom_tool -> doc-level tool
	extractor.docGetters["sbom_tool"] = func(d sbom.Document) []string {
		sbomTools := []string{}
		for _, t := range d.Tools() {
			sbomTools = append(sbomTools, t.GetName())
		}
		return nilOrSlice(sbomTools)
	}

	// sbom_lifecycle -> doc-level lifecycle
	extractor.docGetters["sbom_lifecycle"] = func(d sbom.Document) []string {
		return nilOrSlice(d.Lifecycles())
	}

	// sbom_pc -> doc-level pc
	extractor.docGetters["sbom_pc"] = func(d sbom.Document) []string {
		primaryComp := []string{}
		primaryComp = append(primaryComp, d.PrimaryComp().GetName())
		primaryComp = append(primaryComp, d.PrimaryComp().GetID())
		return nilOrSlice(primaryComp)
	}

	return extractor
}

// nilOrSlice returns nil if the provided slice is empty,
// otherwise the slice itself.
func nilOrSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
