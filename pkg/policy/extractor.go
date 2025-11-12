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
	"context"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// Extractor provides a simple mapping from canonical field names to
// component-level or document-level.
type Extractor struct {
	Doc         sbom.Document
	compGetters map[string]func(sbom.GetComponent) []string
	docGetters  map[string]func(sbom.Document) []string
}

func NewExtractor(doc sbom.Document) *Extractor {
	return &Extractor{
		Doc:         doc,
		compGetters: map[string]func(sbom.GetComponent) []string{},
		docGetters:  map[string]func(sbom.Document) []string{},
	}
}

// MapFieldWithFunction creates an Extractor for SBOM fields.
// quick mapping of fields with respective funtions
func (extractor *Extractor) MapFieldWithFunction(ctx context.Context) {
	log := logger.FromContext(ctx)
	log.Debugf("Creating Extractor...")

	// component-level mappings (canonical keys are lowercase)
	extractor.compGetters["name"] = func(c sbom.GetComponent) []string {
		if s := c.GetName(); s != "" {
			log.Debugf("exracted name field: %s", s)
			return []string{s}
		}
		return nil
	}

	extractor.compGetters["version"] = func(c sbom.GetComponent) []string {
		if s := c.GetVersion(); s != "" {
			log.Debugf("exracted version field: %s", s)
			return []string{s}
		}
		return nil
	}

	extractor.compGetters["license"] = func(c sbom.GetComponent) []string {
		licenses := []string{}
		if len(c.GetLicenses()) == 0 {
			licenses = append(licenses, "NOASSERTION")
		}

		for _, l := range c.GetLicenses() {
			// preferring ID instead of Name, coz, user prefer ID over names.
			if ln := l.ShortID(); ln != "" {
				licenses = append(licenses, ln)
			}
		}
		log.Debugf("exracted license value: %s", licenses)

		return nilOrSlice(licenses)
	}

	extractor.compGetters["purl"] = func(c sbom.GetComponent) []string {
		purls := []string{}
		for _, p := range c.GetPurls() {
			if s := p.String(); s != "" {
				purls = append(purls, s)
			}
		}

		log.Debugf("exracted PURL field: %s", purls)
		return nilOrSlice(purls)
	}

	extractor.compGetters["cpe"] = func(c sbom.GetComponent) []string {
		log.Debugf("exracted field: cpe")

		cpes := []string{}
		for _, cp := range c.GetCpes() {
			if s := cp.String(); s != "" {
				cpes = append(cpes, s)
			}
		}

		log.Debugf("exracted CPE field: %s", cpes)
		return nilOrSlice(cpes)
	}

	extractor.compGetters["copyright"] = func(c sbom.GetComponent) []string {
		if s := c.GetCopyRight(); s != "" {
			log.Debugf("exracted copyright field: %s", s)
			return []string{s}
		}
		return nil
	}

	// keep canonical key lowercase: "downloadlocation" to avoid special chars in lookups
	extractor.compGetters["downloadlocation"] = func(c sbom.GetComponent) []string {
		if s := c.GetDownloadLocationURL(); s != "" {
			log.Debugf("exracted downloadlocation field: %s", s)
			return []string{s}
		}
		return nil
	}

	// canonical "type" (primary purpose)
	extractor.compGetters["type"] = func(c sbom.GetComponent) []string {
		log.Debugf("exracted field: type")

		if s := c.PrimaryPurpose(); s != "" {
			log.Debugf("exracted package type field: %s", s)
			return []string{s}
		}
		return nil
	}

	// supplier: aggregate common supplier fields
	extractor.compGetters["supplier"] = func(c sbom.GetComponent) []string {
		log.Debugf("exracted field: supplier")

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
		log.Debugf("exracted suppliers field: %s", suppliers)
		return nilOrSlice(suppliers)
	}

	// author: aggregate common author fields
	extractor.compGetters["author"] = func(c sbom.GetComponent) []string {
		log.Debugf("exracted field: author")

		authors := []string{}

		if c != nil {
			for _, a := range c.Authors() {
				authors = append(authors, a.GetName())
				authors = append(authors, a.GetEmail())
			}
		}

		log.Debugf("exracted authors field: %s", authors)
		return nilOrSlice(authors)
	}

	// author: aggregate common author fields
	extractor.compGetters["checksum"] = func(c sbom.GetComponent) []string {
		log.Debugf("exracted field: checksum")

		var cheksums []string
		for _, chk := range c.GetChecksums() {
			cheksums = append(cheksums, chk.GetContent())
		}

		log.Debugf("exracted cheksums field: %s", cheksums)
		return nilOrSlice(cheksums)
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
}

// nilOrSlice returns nil if the provided slice is empty,
// otherwise the slice itself.
func nilOrSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Values returns a slice of string values for the given field on the
// provided component. Lookup rules:
//   - If field starts with "sbom_" → resolve against doc-level getters only.
//   - Otherwise → resolve against component-level getters only.
//
// Field name is normalized to lowercase.
func (e *Extractor) RetrieveValues(comp sbom.GetComponent, field string) []string {
	if e == nil {
		return nil
	}
	f := strings.ToLower(strings.TrimSpace(field))

	// document-level
	if strings.HasPrefix(f, "sbom_") {
		if getDocField, ok := e.docGetters[f]; ok {
			return getDocField(e.Doc)
		}
		return nil
	}

	// component-level
	if getCompField, ok := e.compGetters[f]; ok {
		return getCompField(comp)
	}
	return nil
}

// HasField returns true if the given field exists and has at least one
// non-empty value. Uses the same prefix rules as Values().
func (extract *Extractor) HasField(comp sbom.GetComponent, field string) bool {
	vals := extract.RetrieveValues(comp, field)
	return len(vals) > 0
}
