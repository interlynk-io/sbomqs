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

// FSCT (Framing Software Component Transparency, 3rd Edition) extractors.
//
// Feature keys and scorer equivalents:
//
//   sbom_provenance        → FSCTSBOMProvenance        (timestamp + author)
//   sbom_primary_component → FSCTSBOMPrimaryComponent  (primary comp name+version)
//   relationships_coverage → FSCTSBOMRelationships     (primary deps + completeness)
//   comp_identity          → FSCTCompIdentity          (name + version per component)
//   supplier_attribution   → FSCTCompSupplier          (supplier or "unknown")
//   comp_unique_id         → FSCTCompUniqID            (PURL/CPE/SWHID/SWID/OmniBOR)
//   artifact_integrity     → FSCTCompChecksum          (any checksum, any algorithm)
//   license_coverage       → FSCTCompLicense           (any license — no format validation)
//   copyright_coverage     → FSCTCompCopyright         (copyright text)
//
// The list command shows actual field values; it does not enforce completeness
// decisions (that is the scorer's job).

package extractors

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	scorercommon "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
)

// fsctDependencyCompleteness returns the composition aggregate declared for compID.
// Mirrors the logic in profiles.DependencyCompleteness:
//  1. ScopeGlobal → applies to all components
//  2. ScopeDependencies with compID in the dependency list → per-component completeness
//  3. Not found → AggregateMissing
func fsctDependencyCompleteness(doc sbom.Document, compID string) sbom.CompositionAggregate {
	for _, c := range doc.Composition() {
		if c.Scope() == sbom.ScopeGlobal {
			return c.Aggregate()
		}
		if c.Scope() != sbom.ScopeDependencies {
			continue
		}
		if slices.Contains(c.Dependencies(), compID) {
			return c.Aggregate()
		}
	}
	return sbom.AggregateMissing
}

// fsctValidateLicenseText mirrors profiles/common.ValidateLicenseText:
// non-empty and not NONE/NOASSERTION.
func fsctValidateLicenseText(s string) bool {
	if s == "" {
		return false
	}
	u := strings.ToUpper(strings.TrimSpace(s))
	return u != "NOASSERTION" && u != "NONE"
}

// ============================================================
// FSCT — SBOM-level extractors (DocExtractor)
// ============================================================

// FSCTSBOMProvenance reports the SBOM timestamp and first usable author identity.
//
// Timestamp: must be RFC3339Nano-compliant.
// Author: SPDX — CreationInfo.Creators (Person/Organization); CDX — metadata.authors.
// Any of name, email, or phone is accepted per FSCT.
// Mirrors: profiles.FSCTSBOMProvenance
func FSCTSBOMProvenance(doc sbom.Document) (bool, string, error) {
	// Timestamp
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	timestampOK := false
	var tsDesc string

	if ts == "" {
		tsDesc = "timestamp: missing"
	} else if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		tsDesc = fmt.Sprintf("timestamp: present but not RFC3339 (%s)", ts)
	} else {
		timestampOK = true
		tsDesc = fmt.Sprintf("timestamp: %s", ts)
	}

	// Author — name, email, or phone from doc.Authors()
	authorDesc := "author: missing"
	authorOK := false

	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		name := strings.TrimSpace(a.GetName())
		email := strings.TrimSpace(a.GetEmail())
		phone := strings.TrimSpace(a.GetPhone())

		if name != "" && email != "" {
			authorDesc = fmt.Sprintf("author: %s <%s>", name, email)
			authorOK = true
			break
		}
		if name != "" {
			authorDesc = fmt.Sprintf("author: %s", name)
			authorOK = true
			break
		}
		if email != "" {
			authorDesc = fmt.Sprintf("author email: %s", email)
			authorOK = true
			break
		}
		if phone != "" {
			authorDesc = fmt.Sprintf("author phone: %s", phone)
			authorOK = true
			break
		}
	}

	value := tsDesc + "; " + authorDesc
	return timestampOK && authorOK, value, nil
}

// FSCTSBOMPrimaryComponent reports the primary component's name and version.
// SPDX: DocumentDescribes. CDX: metadata.component.
// Mirrors: profiles.FSCTSBOMPrimaryComponent
func FSCTSBOMPrimaryComponent(doc sbom.Document) (bool, string, error) {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return false, "no primary component declared", nil
	}

	name := strings.TrimSpace(primary.GetName())
	version := strings.TrimSpace(primary.GetVersion())

	if name == "" && version == "" {
		return false, "primary component declared but name and version missing", nil
	}
	if name == "" {
		return false, fmt.Sprintf("primary component declared but name missing (version: %s)", version), nil
	}
	if version == "" {
		return false, fmt.Sprintf("primary component declared but version missing (name: %s)", name), nil
	}

	return true, fmt.Sprintf("%s %s", name, version), nil
}

// FSCTSBOMRelationships reports the dependency relationship and completeness status.
//
// FSCT requires:
//  1. Completeness declared for the primary component.
//  2. Completeness declared for each of its direct DEPENDS_ON dependencies.
//
// Mirrors: profiles.FSCTSBOMRelationships + profiles.DependencyCompleteness
func FSCTSBOMRelationships(doc sbom.Document) (bool, string, error) {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return false, "no primary component declared", nil
	}

	primaryAgg := fsctDependencyCompleteness(doc, primary.GetID())
	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	if primaryAgg == sbom.AggregateMissing {
		return false, fmt.Sprintf("%d direct deps declared; completeness missing for primary component", len(directDeps)), nil
	}

	// Check completeness for each direct dependency
	missing := 0
	for _, dep := range directDeps {
		if fsctDependencyCompleteness(doc, dep.GetID()) == sbom.AggregateMissing {
			missing++
		}
	}

	total := len(directDeps)
	if missing > 0 {
		return false, fmt.Sprintf(
			"%d direct deps; primary completeness: %s; completeness missing for %d/%d direct deps",
			total, string(primaryAgg), missing, total,
		), nil
	}

	if total == 0 {
		return true, fmt.Sprintf("no direct deps; primary completeness: %s", string(primaryAgg)), nil
	}
	return true, fmt.Sprintf(
		"%d direct deps; primary completeness: %s; all direct deps have completeness declared",
		total, string(primaryAgg),
	), nil
}

// ============================================================
// FSCT — component-level extractors (CompExtractor)
// ============================================================

// FSCTCompIdentity reports the component's name and version.
// Both must be non-empty for FSCT compliance.
// Mirrors: profiles.FSCTCompIdentity
func FSCTCompIdentity(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	name := strings.TrimSpace(comp.GetName())
	version := strings.TrimSpace(comp.GetVersion())

	if name != "" && version != "" {
		return true, fmt.Sprintf("%s %s", name, version), nil
	}
	if name == "" && version == "" {
		return false, "name and version missing", nil
	}
	if name == "" {
		return false, fmt.Sprintf("name missing (version: %s)", version), nil
	}
	return false, fmt.Sprintf("version missing (name: %s)", name), nil
}

// FSCTCompSupplier reports the component supplier.
// SPDX: PackageSupplier. CDX: components[].supplier.
//
// FSCT accepts "unknown" as a valid explicit declaration.
// Shows name, URL, email, or contact info — whichever is present.
// Mirrors: profiles.FSCTCompSupplier
func FSCTCompSupplier(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	s := comp.Suppliers()
	if s == nil || s.IsAbsent() {
		return false, "missing", nil
	}

	name := strings.TrimSpace(s.GetName())
	url := strings.TrimSpace(s.GetURL())
	email := strings.TrimSpace(s.GetEmail())

	// Contacts (name or email on contact record)
	var contactInfo string
	for _, c := range s.GetContacts() {
		cn := strings.TrimSpace(c.GetName())
		ce := strings.TrimSpace(c.GetEmail())
		if cn != "" || ce != "" {
			if cn != "" && ce != "" {
				contactInfo = fmt.Sprintf("%s <%s>", cn, ce)
			} else if cn != "" {
				contactInfo = cn
			} else {
				contactInfo = ce
			}
			break
		}
	}

	// Explicitly declared as unknown — still valid per FSCT
	if strings.EqualFold(name, "unknown") {
		return true, "unknown (declared)", nil
	}

	if name != "" || url != "" || email != "" || contactInfo != "" {
		var parts []string
		if name != "" {
			parts = append(parts, name)
		}
		if email != "" {
			parts = append(parts, email)
		}
		if url != "" {
			parts = append(parts, url)
		}
		if contactInfo != "" && name == "" {
			parts = append(parts, fmt.Sprintf("contact: %s", contactInfo))
		}
		return true, strings.Join(parts, ", "), nil
	}

	return false, "missing", nil
}

// FSCTCompUniqID reports the unique identifier(s) for the component.
// FSCT accepts: PURL, CPE, SWHID, SWID, OmniBOR — any one suffices.
// Shows all found identifiers.
// Mirrors: profiles.FSCTCompUniqID + detectFsctUniqueIDTypes
func FSCTCompUniqID(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var found []string

	for _, p := range comp.GetPurls() {
		if s := strings.TrimSpace(string(p)); s != "" {
			found = append(found, fmt.Sprintf("purl: %s", s))
			break // show first only; one per type is enough for display
		}
	}
	for _, c := range comp.GetCpes() {
		if s := strings.TrimSpace(string(c)); s != "" {
			found = append(found, fmt.Sprintf("cpe: %s", s))
			break
		}
	}
	for _, id := range comp.Swhids() {
		if s := strings.TrimSpace(string(id)); s != "" {
			found = append(found, fmt.Sprintf("swhid: %s", s))
			break
		}
	}
	for _, id := range comp.Swids() {
		if s := strings.TrimSpace(id.String()); s != "" {
			found = append(found, fmt.Sprintf("swid: %s", s))
			break
		}
	}
	for _, id := range comp.OmniborIDs() {
		if s := strings.TrimSpace(string(id)); s != "" {
			found = append(found, fmt.Sprintf("omnibor: %s", s))
			break
		}
	}

	if len(found) > 0 {
		return true, strings.Join(found, "; "), nil
	}
	return false, "missing (no PURL, CPE, SWHID, SWID, or OmniBOR)", nil
}

// FSCTCompHash reports the first available cryptographic hash on the component.
// FSCT does not mandate a specific algorithm — any hash suffices.
// CDX: component.hashes. SPDX: PackageChecksum.
// Mirrors: profiles.FSCTCompChecksum
func FSCTCompHash(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, chk := range comp.GetChecksums() {
		algo := scorercommon.NormalizeAlgoName(chk.GetAlgo())
		content := strings.TrimSpace(chk.GetContent())
		if content != "" {
			return true, fmt.Sprintf("%s: %s", algo, content), nil
		}
	}
	return false, "missing", nil
}

// FSCTCompLicense reports the first available license on the component.
// FSCT does not require SPDX identifiers or license validation —
// any non-empty, non-NONE/NOASSERTION value is accepted.
// Checks concluded licences first, declared licences second.
// Mirrors: profiles.FSCTCompLicense + common.ComponentHasAnyLicense
func FSCTCompLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, l := range comp.ConcludedLicenses() {
		if l == nil {
			continue
		}
		if id := strings.TrimSpace(l.ShortID()); fsctValidateLicenseText(id) {
			return true, fmt.Sprintf("concluded: %s", id), nil
		}
		if name := strings.TrimSpace(l.Name()); fsctValidateLicenseText(name) {
			return true, fmt.Sprintf("concluded: %s", name), nil
		}
	}
	for _, l := range comp.DeclaredLicenses() {
		if l == nil {
			continue
		}
		if id := strings.TrimSpace(l.ShortID()); fsctValidateLicenseText(id) {
			return true, fmt.Sprintf("declared: %s", id), nil
		}
		if name := strings.TrimSpace(l.Name()); fsctValidateLicenseText(name) {
			return true, fmt.Sprintf("declared: %s", name), nil
		}
	}
	return false, "missing", nil
}

// FSCTCompCopyright reports the copyright text for the component.
// FSCT does not mandate a specific format — any non-empty, non-NONE/NOASSERTION value is accepted.
// SPDX: PackageCopyrightText. CDX: component.copyright (if supported).
// Mirrors: profiles.FSCTCompCopyright
func FSCTCompCopyright(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	val := strings.TrimSpace(comp.GetCopyRight())
	if fsctValidateLicenseText(val) {
		return true, val, nil
	}
	if val == "" {
		return false, "missing", nil
	}
	return false, fmt.Sprintf("present but invalid: %s", val), nil
}
