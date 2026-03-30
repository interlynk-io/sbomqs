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

// Generic extractors are profile-independent. They show raw field values
// without applying any compliance-specific acceptance rules (e.g. no
// NONE/NOASSERTION filtering, no algorithm enforcement). They are used
// when no --profile flag is provided.

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// GenericCompExternalRefs shows all external references declared on a component.
// CDX: externalReferences[]. SPDX: externalRefs[].
// Each entry is formatted as "type: locator"; entries are separated by "; ".
func GenericCompExternalRefs(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var parts []string
	for _, er := range comp.ExternalReferences() {
		t := strings.TrimSpace(er.GetRefType())
		loc := strings.TrimSpace(er.GetRefLocator())
		switch {
		case t != "" && loc != "":
			parts = append(parts, fmt.Sprintf("%s: %s", t, loc))
		case loc != "":
			parts = append(parts, loc)
		case t != "":
			parts = append(parts, t)
		}
	}
	if len(parts) > 0 {
		return true, strings.Join(parts, "; "), nil
	}
	return false, "no external references", nil
}

// GenericCompAllLicenses shows all license information on a component across
// both concluded and declared fields, each labeled by type.
// No compliance filtering is applied — NONE/NOASSERTION values are shown as-is.
func GenericCompAllLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var parts []string
	for _, l := range comp.ConcludedLicenses() {
		if l == nil {
			continue
		}
		if id := strings.TrimSpace(l.ShortID()); id != "" {
			parts = append(parts, fmt.Sprintf("concluded: %s", id))
		}
	}
	for _, l := range comp.DeclaredLicenses() {
		if l == nil {
			continue
		}
		if id := strings.TrimSpace(l.ShortID()); id != "" {
			parts = append(parts, fmt.Sprintf("declared: %s", id))
		}
	}
	if len(parts) > 0 {
		return true, strings.Join(parts, "; "), nil
	}
	return false, "missing", nil
}

// GenericCompDepth shows the direct dependencies of a component by name.
// If the component is present in the dependency graph but has no outgoing
// edges it is reported as "leaf component". Components absent from the
// graph entirely are reported as "not in dependency graph".
func GenericCompDepth(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	outgoing := doc.GetOutgoingRelations(comp.GetID())
	count := len(outgoing)

	// A component is "in the graph" if it has outgoing deps OR appears as
	// a target of any other component's relationship.
	inGraph := count > 0
	if !inGraph {
		for _, r := range doc.GetRelationships() {
			if r.GetTo() == comp.GetID() {
				inGraph = true
				break
			}
		}
	}

	if !inGraph {
		return false, "not in dependency graph", nil
	}
	if count == 0 {
		return true, "leaf component", nil
	}

	// Build an ID→name lookup so we can show human-readable names.
	nameByID := make(map[string]string, len(doc.Components()))
	for _, c := range doc.Components() {
		nameByID[c.GetID()] = c.GetName()
	}

	depNames := make([]string, 0, count)
	for _, r := range outgoing {
		id := r.GetTo()
		if name := nameByID[id]; name != "" {
			depNames = append(depNames, name)
		} else {
			depNames = append(depNames, id)
		}
	}
	return true, fmt.Sprintf("%d direct deps: %s", count, strings.Join(depNames, ", ")), nil
}

// GenericCompSupplier shows the supplier or manufacturer of a component.
// Supplier is checked first; manufacturer is used as a fallback and is
// labeled "(manufacturer)" to distinguish the source.
// Name, email, and URL are all shown where present.
func GenericCompSupplier(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if s := comp.Suppliers(); s != nil && !s.IsAbsent() {
		var parts []string
		if name := strings.TrimSpace(s.GetName()); name != "" {
			parts = append(parts, name)
		}
		if email := strings.TrimSpace(s.GetEmail()); email != "" {
			parts = append(parts, email)
		}
		if u := strings.TrimSpace(s.GetURL()); u != "" {
			parts = append(parts, u)
		}
		if len(parts) > 0 {
			return true, strings.Join(parts, ", "), nil
		}
	}

	if m := comp.Manufacturer(); m != nil && !m.IsAbsent() {
		var parts []string
		if name := strings.TrimSpace(m.GetName()); name != "" {
			parts = append(parts, name)
		}
		if email := strings.TrimSpace(m.GetEmail()); email != "" {
			parts = append(parts, email)
		}
		if u := strings.TrimSpace(m.GetURL()); u != "" {
			parts = append(parts, u)
		}
		if len(parts) > 0 {
			return true, fmt.Sprintf("%s (manufacturer)", strings.Join(parts, ", ")), nil
		}
	}

	return false, "missing", nil
}

// GenericCompAuthor shows all authors declared on a component.
// CDX: components[].authors[]. SPDX: not supported at component level.
// Each author is formatted as "Name <email>" where both fields are present.
func GenericCompAuthor(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var parts []string
	for _, a := range comp.Authors() {
		name := strings.TrimSpace(a.GetName())
		email := strings.TrimSpace(a.GetEmail())
		switch {
		case name != "" && email != "":
			parts = append(parts, fmt.Sprintf("%s <%s>", name, email))
		case name != "":
			parts = append(parts, name)
		case email != "":
			parts = append(parts, email)
		}
	}
	if len(parts) > 0 {
		return true, strings.Join(parts, "; "), nil
	}
	return false, "missing", nil
}

// GenericCompUniqIDs shows all unique identifiers present on a component:
// PURL, CPE, SWHID, SWID, and OmniBOR. All found values are shown,
// each labeled by type, separated by "; ".
func GenericCompUniqIDs(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var found []string
	for _, p := range comp.GetPurls() {
		if s := strings.TrimSpace(string(p)); s != "" {
			found = append(found, fmt.Sprintf("purl: %s", s))
		}
	}
	for _, c := range comp.GetCpes() {
		if s := strings.TrimSpace(string(c)); s != "" {
			found = append(found, fmt.Sprintf("cpe: %s", s))
		}
	}
	for _, id := range comp.Swhids() {
		if s := strings.TrimSpace(string(id)); s != "" {
			found = append(found, fmt.Sprintf("swhid: %s", s))
		}
	}
	for _, id := range comp.Swids() {
		if s := strings.TrimSpace(id.String()); s != "" {
			found = append(found, fmt.Sprintf("swid: %s", s))
		}
	}
	for _, id := range comp.OmniborIDs() {
		if s := strings.TrimSpace(string(id)); s != "" {
			found = append(found, fmt.Sprintf("omnibor: %s", s))
		}
	}
	if len(found) > 0 {
		return true, strings.Join(found, "; "), nil
	}
	return false, "missing (no PURL, CPE, SWHID, SWID, or OmniBOR)", nil
}

// GenericSBOMPrimaryComp reports the primary component of the SBOM.
// CDX: metadata.component. SPDX: described package (if set).
// Shows the component name and version where available.
func GenericSBOMPrimaryComp(doc sbom.Document) (bool, string, error) {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return false, "no primary component declared", nil
	}
	name := strings.TrimSpace(primary.GetName())
	version := strings.TrimSpace(primary.GetVersion())
	switch {
	case name != "" && version != "":
		return true, fmt.Sprintf("%s %s", name, version), nil
	case name != "":
		return true, name, nil
	case version != "":
		return true, fmt.Sprintf("(version: %s)", version), nil
	default:
		return false, "primary component declared but name and version missing", nil
	}
}
