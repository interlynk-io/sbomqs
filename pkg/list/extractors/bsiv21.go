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

// BSI v2.1 extractors mirror the logic in pkg/scorer/v2/profiles/bsiv21.go
// but work per-component and return the actual field value for display.
//
// SPDX note: BSI v2.1 officially requires CDX >= 1.6 or SPDX >= 3.0.1.
// SPDX v3 is not yet supported by the parser. Where SPDX v2 fields map
// meaningfully to BSI concepts, they are extracted anyway (same behaviour
// as the bsiv20 scorer profile).

package extractors

import (
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	scorercommon "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
)

func bsiIsValidEmail(e string) bool {
	e = strings.TrimSpace(e)
	if e == "" {
		return false
	}
	_, err := mail.ParseAddress(e)
	return err == nil
}

func bsiIsValidURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	parsed, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	return parsed.Scheme != "" && parsed.Host != ""
}

func bsiIsVersionAtLeast(version, minVersion string) bool {
	parseParts := func(v string) (int, int) {
		parts := strings.Split(v, ".")
		major, minor := 0, 0
		if len(parts) >= 1 {
			fmt.Sscanf(parts[0], "%d", &major)
		}
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &minor)
		}
		return major, minor
	}
	vMajor, vMinor := parseParts(version)
	mMajor, mMinor := parseParts(minVersion)
	if vMajor > mMajor {
		return true
	}
	return vMajor == mMajor && vMinor >= mMinor
}

// bsiIsAcceptableLicense mirrors isAcceptableLicense from profiles/bsiv11.go.
// Accepts valid SPDX IDs and properly-formatted LicenseRef-* identifiers.
// Rejects NONE, NOASSERTION, and empty values.
func bsiIsAcceptableLicense(l licenses.License) bool {
	id := l.ShortID()
	if id == "" {
		return false
	}
	u := strings.ToUpper(strings.TrimSpace(id))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}
	if l.Spdx() {
		return true
	}
	if l.Custom() && strings.HasPrefix(id, "LicenseRef-") {
		return true
	}
	return false
}

// SBOM-level (DocExtractor)

// BSIV21SpecVersion checks the SBOM spec version against BSI v2.1 minimums:
// CDX >= 1.6, SPDX >= 3.0.1.
// Mirrors: profiles.BSIV21SpecVersion
func BSIV21SpecVersion(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == "" || ver == "" {
		return false, "spec type or version missing", nil
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		if bsiIsVersionAtLeast(ver, "1.6") {
			return true, fmt.Sprintf("CycloneDX %s (meets >= 1.6)", ver), nil
		}
		return false, fmt.Sprintf("CycloneDX %s (requires >= 1.6)", ver), nil

	case string(sbom.SBOMSpecSPDX):
		if bsiIsVersionAtLeast(ver, "3.0") {
			return true, fmt.Sprintf("SPDX %s (meets >= 3.0.1)", ver), nil
		}
		return false, fmt.Sprintf("SPDX %s (requires >= 3.0.1; SPDX v2 not allowed by BSI v2.1)", ver), nil
	}

	return false, fmt.Sprintf("unsupported spec: %s", spec), nil
}

// BSIV21SBOMCreator checks that at least one valid contact channel (email or URL)
// is declared for the SBOM creator.
// Sources: authors email, manufacturer email/URL, supplier email/URL.
// Mirrors: profiles.BSIV11SBOMCreator
func BSIV21SBOMCreator(doc sbom.Document) (bool, string, error) {
	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		if bsiIsValidEmail(a.GetEmail()) {
			return true, fmt.Sprintf("author email: %s", a.GetEmail()), nil
		}
	}

	if m := doc.Manufacturer(); m != nil {
		if bsiIsValidEmail(m.GetEmail()) {
			return true, fmt.Sprintf("manufacturer email: %s", m.GetEmail()), nil
		}
		if bsiIsValidURL(m.GetURL()) {
			return true, fmt.Sprintf("manufacturer url: %s", m.GetURL()), nil
		}
		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return true, fmt.Sprintf("manufacturer contact email: %s", c.GetEmail()), nil
			}
		}
	}

	if s := doc.Supplier(); s != nil {
		if bsiIsValidEmail(s.GetEmail()) {
			return true, fmt.Sprintf("supplier email: %s", s.GetEmail()), nil
		}
		if bsiIsValidURL(s.GetURL()) {
			return true, fmt.Sprintf("supplier url: %s", s.GetURL()), nil
		}
		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return true, fmt.Sprintf("supplier contact email: %s", c.GetEmail()), nil
			}
		}
	}

	return false, "missing", nil
}

// BSIV21SBOMTimestamp checks that the SBOM creation timestamp is present and RFC3339-compliant.
// Mirrors: profiles.BSIV11SBOMCreationTimestamp
func BSIV21SBOMTimestamp(doc sbom.Document) (bool, string, error) {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return false, "missing", nil
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return false, fmt.Sprintf("invalid timestamp: %s (not RFC3339)", ts), nil
	}
	return true, ts, nil
}

// BSIV21SBOMURI checks that the SBOM-URI is declared and valid.
// CDX: serialNumber. SPDX: documentNamespace.
// Mirrors: profiles.BSIV21SBOMURI
func BSIV21SBOMURI(doc sbom.Document) (bool, string, error) {
	candidate := strings.TrimSpace(doc.Spec().GetURI())
	if candidate == "" {
		candidate = strings.TrimSpace(doc.Spec().GetNamespace())
	}
	if candidate == "" {
		return false, "missing", nil
	}
	if !bsiIsValidURL(candidate) && !strings.HasPrefix(candidate, "urn:") {
		return false, fmt.Sprintf("present but invalid: %s", candidate), nil
	}
	return true, candidate, nil
}

// Component-level (CompExtractor)

// BSIV21CompCreator checks that each component declares a valid creator contact
// (email or URL) via authors, manufacturer, or supplier.
// CDX: comp.Authors / comp.Manufacturer / comp.Suppliers.
// SPDX v2: PackageOriginator / PackageSupplier (via Suppliers / originator fields).
// Mirrors: profiles.BSIV11CompCreator
func BSIV21CompCreator(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// Authors
	for _, a := range comp.Authors() {
		if a != nil && bsiIsValidEmail(a.GetEmail()) {
			return true, fmt.Sprintf("author email: %s", a.GetEmail()), nil
		}
	}

	// Manufacturer
	if m := comp.Manufacturer(); !m.IsAbsent() {
		if bsiIsValidEmail(m.GetEmail()) {
			return true, fmt.Sprintf("manufacturer email: %s", m.GetEmail()), nil
		}
		if bsiIsValidURL(m.GetURL()) {
			return true, fmt.Sprintf("manufacturer url: %s", m.GetURL()), nil
		}
		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return true, fmt.Sprintf("manufacturer contact email: %s", c.GetEmail()), nil
			}
		}
	}

	// Supplier
	if s := comp.Suppliers(); !s.IsAbsent() {
		if bsiIsValidEmail(s.GetEmail()) {
			return true, fmt.Sprintf("supplier email: %s", s.GetEmail()), nil
		}
		if bsiIsValidURL(s.GetURL()) {
			return true, fmt.Sprintf("supplier url: %s", s.GetURL()), nil
		}
		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return true, fmt.Sprintf("supplier contact email: %s", c.GetEmail()), nil
			}
		}
	}

	return false, "missing", nil
}

// BSIV21CompName checks that the component name is declared.
// Mirrors: profiles.BSIV11CompName
func BSIV21CompName(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	name := strings.TrimSpace(comp.GetName())
	if name != "" {
		return true, name, nil
	}
	return false, "missing", nil
}

// BSIV21CompVersion checks that the component version is declared.
// Mirrors: profiles.BSIV11CompVersion
func BSIV21CompVersion(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	ver := strings.TrimSpace(comp.GetVersion())
	if ver != "" {
		return true, ver, nil
	}
	return false, "missing", nil
}

// BSIV21CompFilename checks for the component filename.
// CDX: bsi:component:filename property.
// SPDX v2: PackageFileName via comp.GetFilename().
// Mirrors: profiles.BSIV21CompFilename / profiles.BSIV20CompFilename (SPDX branch)
func BSIV21CompFilename(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		val := strings.TrimSpace(comp.GetPropertyValue("bsi:component:filename"))
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		val := strings.TrimSpace(comp.GetFilename())
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompDepth shows the component's position in the dependency graph.
// BSI v2.1 requires a fully-declared dependency graph at the document level.
// CDX stores dependency data in the top-level dependencies[] array (not on
// individual components), so this extractor queries the document relationship
// graph via doc.GetOutgoingRelations / doc.GetRelationships.
// A component is "in the graph" if it appears as a source (even with 0 deps,
// i.e. a leaf) or as a target of any relationship.
// Mirrors: profiles.BSIV20CompDependencies (per-component view)
func BSIV21CompDepth(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	outgoing := doc.GetOutgoingRelations(comp.GetID())
	count := len(outgoing)

	// Check if this component appears anywhere in the dependency graph
	// (as source with outgoing deps, or as a target of another component).
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
		return true, "leaf node (0 direct deps)", nil
	}

	depIDs := make([]string, 0, count)
	for _, r := range outgoing {
		depIDs = append(depIDs, r.GetTo())
	}
	return true, fmt.Sprintf("%d direct deps: %s", count, strings.Join(depIDs, ", ")), nil
}

// BSIV21CompDistributionLicense checks for concluded licences (distribution licence per BSI v2.1).
// Accepts valid SPDX IDs and LicenseRef-* identifiers; rejects NONE/NOASSERTION.
// Mirrors: profiles.BSIV21CompDistributionLicence
func BSIV21CompDistributionLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var accepted []string
	for _, l := range comp.ConcludedLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			accepted = append(accepted, l.ShortID())
		}
	}
	if len(accepted) > 0 {
		return true, strings.Join(accepted, ", "), nil
	}
	return false, "missing", nil
}

// BSIV21CompDeployableHash extracts the hash on the deployable component.
// CDX: any hash on externalReferences[type=distribution or distribution-intake].
//
//	Note: BSI v2.1 requires SHA-512 specifically; the list command shows the
//	actual value present so the user can cross-check what the scorer enforces.
//
// SPDX v2: any PackageChecksum on the component.
// Mirrors: profiles.BSIV21CompDeployableHash (CDX) + profiles.BSIV20CompDeployableHash (SPDX branch)
func BSIV21CompDeployableHash(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		for _, er := range comp.ExternalReferences() {
			t := er.GetRefType()
			if t != "distribution" && t != "distribution-intake" {
				continue
			}
			for _, h := range er.GetRefHashes() {
				algo := scorercommon.NormalizeAlgoName(h.GetAlgo())
				content := strings.TrimSpace(h.GetContent())
				if content != "" {
					return true, fmt.Sprintf("%s: %s", algo, content), nil
				}
			}
		}
		return false, "missing (no hash on distribution extref)", nil

	case string(sbom.SBOMSpecSPDX):
		for _, chk := range comp.GetChecksums() {
			algo := scorercommon.NormalizeAlgoName(chk.GetAlgo())
			content := strings.TrimSpace(chk.GetContent())
			if content != "" {
				return true, fmt.Sprintf("%s: %s", algo, content), nil
			}
		}
		return false, "missing (no checksum)", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompExecutableProp checks the executable property for the component.
// CDX: bsi:component:executable property.
// SPDX v2: PrimaryPackagePurpose = APPLICATION.
// Mirrors: profiles.BSIV21CompExecutableProperty / profiles.BSIV20CompExecutableProperty
func BSIV21CompExecutableProp(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		val := strings.TrimSpace(comp.GetPropertyValue("bsi:component:executable"))
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(comp.PrimaryPurpose()))
		if purpose == "APPLICATION" {
			return true, purpose, nil
		}
		if purpose != "" {
			return false, fmt.Sprintf("purpose: %s (not APPLICATION)", purpose), nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompArchiveProp checks the archive property for the component.
// CDX: bsi:component:archive property.
// SPDX v2: PrimaryPackagePurpose = ARCHIVE.
// Mirrors: profiles.BSIV21CompArchiveProperty / profiles.BSIV20CompArchiveProperty
func BSIV21CompArchiveProp(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		val := strings.TrimSpace(comp.GetPropertyValue("bsi:component:archive"))
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(comp.PrimaryPurpose()))
		if purpose == "ARCHIVE" {
			return true, purpose, nil
		}
		if purpose != "" {
			return false, fmt.Sprintf("purpose: %s (not ARCHIVE)", purpose), nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompStructuredProp checks the structured property for the component.
// CDX: bsi:component:structured property.
// SPDX v2: PrimaryPackagePurpose = SOURCE.
// Mirrors: profiles.BSIV21CompStructuredProperty / profiles.BSIV20CompStructuredProperty
func BSIV21CompStructuredProp(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		val := strings.TrimSpace(comp.GetPropertyValue("bsi:component:structured"))
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		purpose := strings.ToUpper(strings.TrimSpace(comp.PrimaryPurpose()))
		if purpose == "SOURCE" {
			return true, purpose, nil
		}
		if purpose != "" {
			return false, fmt.Sprintf("purpose: %s (not SOURCE)", purpose), nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompSourceCodeURL extracts the source code URI for the component.
// CDX: externalReferences[type=source-distribution or vcs].url.
// SPDX v2: GetSourceCodeURL() (PackageSourceInfo / VCS external ref).
// Mirrors: profiles.BSIV21CompSourceCodeURI / profiles.BSIV11CompSourceURI (SPDX branch)
func BSIV21CompSourceCodeURL(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		for _, er := range comp.ExternalReferences() {
			t := er.GetRefType()
			if t != "source-distribution" && t != "vcs" {
				continue
			}
			loc := strings.TrimSpace(er.GetRefLocator())
			if loc != "" {
				return true, fmt.Sprintf("%s: %s", t, loc), nil
			}
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		url := strings.TrimSpace(comp.GetSourceCodeURL())
		if url != "" {
			return true, url, nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompDownloadURL extracts the deployable form URI for the component.
// CDX: externalReferences[type=distribution or distribution-intake].url.
// SPDX v2: PackageDownloadLocation via comp.GetDownloadLocationURL().
// Mirrors: profiles.BSIV21CompDownloadURI / profiles.BSIV11CompExecutableURI (SPDX branch)
func BSIV21CompDownloadURL(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		for _, er := range comp.ExternalReferences() {
			t := er.GetRefType()
			if t != "distribution" && t != "distribution-intake" {
				continue
			}
			loc := strings.TrimSpace(er.GetRefLocator())
			if loc != "" {
				return true, fmt.Sprintf("%s: %s", t, loc), nil
			}
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		loc := strings.TrimSpace(comp.GetDownloadLocationURL())
		if loc != "" {
			return true, loc, nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompOtherIdentifiers extracts CPE, PURL, and SWID identifiers.
// Mirrors: profiles.BSIV21CompOtherIdentifiers
func BSIV21CompOtherIdentifiers(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var all []string

	for _, p := range comp.GetPurls() {
		if s := strings.TrimSpace(string(p)); s != "" {
			all = append(all, s)
		}
	}
	for _, c := range comp.GetCpes() {
		if s := strings.TrimSpace(string(c)); s != "" {
			all = append(all, s)
		}
	}
	for _, sw := range comp.Swids() {
		if id := strings.TrimSpace(sw.GetTagID()); id != "" {
			all = append(all, fmt.Sprintf("swid:%s", id))
		}
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}
	return false, "missing", nil
}

// BSIV21CompOriginalLicenses extracts declared licences (original licences per BSI v2.1).
// Accepts valid SPDX IDs and LicenseRef-* identifiers; rejects NONE/NOASSERTION.
// Mirrors: profiles.BSIV21CompOriginalLicences
func BSIV21CompOriginalLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var accepted []string
	for _, l := range comp.DeclaredLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			accepted = append(accepted, l.ShortID())
		}
	}
	if len(accepted) > 0 {
		return true, strings.Join(accepted, ", "), nil
	}
	return false, "missing", nil
}

// BSIV21CompEffectiveLicense extracts the effective licence property.
// CDX: bsi:component:effectiveLicense property.
// SPDX v2: no equivalent field available.
// Mirrors: profiles.BSIV21CompEffectiveLicence
func BSIV21CompEffectiveLicense(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		val := strings.TrimSpace(comp.GetPropertyValue("bsi:component:effectiveLicense"))
		if val != "" {
			return true, val, nil
		}
		return false, "missing", nil

	case string(sbom.SBOMSpecSPDX):
		return false, "not available in SPDX v2", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompSourceHash extracts the source code hash for the component.
// CDX: any hash on externalReferences[type=source-distribution or vcs].
//
//	Note: BSI v2.1 requires SHA-512 specifically; the list command shows the
//	actual value present so the user can cross-check what the scorer enforces.
//
// SPDX v2: PackageVerificationCode / SourceCodeHash via comp.SourceCodeHash().
// Mirrors: profiles.BSIV21CompSourceHash
func BSIV21CompSourceHash(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		for _, er := range comp.ExternalReferences() {
			t := er.GetRefType()
			if t != "source-distribution" && t != "vcs" {
				continue
			}
			for _, h := range er.GetRefHashes() {
				algo := scorercommon.NormalizeAlgoName(h.GetAlgo())
				content := strings.TrimSpace(h.GetContent())
				if content != "" {
					return true, fmt.Sprintf("%s: %s", algo, content), nil
				}
			}
		}
		return false, "missing (no hash on source-distribution/vcs extref)", nil

	case string(sbom.SBOMSpecSPDX):
		hash := strings.TrimSpace(comp.SourceCodeHash())
		if hash != "" {
			return true, hash, nil
		}
		return false, "missing", nil
	}

	return false, "unsupported spec", nil
}

// BSIV21CompSecurityTxtURL extracts the security.txt URL from externalReferences[type=rfc-9116].
// Mirrors: profiles.BSIV21CompSecurityTxtURL
func BSIV21CompSecurityTxtURL(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, er := range comp.ExternalReferences() {
		if er.GetRefType() == "rfc-9116" {
			loc := strings.TrimSpace(er.GetRefLocator())
			if loc != "" {
				return true, loc, nil
			}
		}
	}
	return false, "missing", nil
}
