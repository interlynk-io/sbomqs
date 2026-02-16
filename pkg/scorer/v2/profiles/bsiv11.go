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

package profiles

import (
	"fmt"
	"strings"
	"time"

	"net/mail"
	"net/url"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// isValidEmail checks whether the given string is a syntactically valid email.
func isValidEmail(e string) bool {
	e = strings.TrimSpace(e)
	if e == "" {
		return false
	}
	_, err := mail.ParseAddress(e)
	return err == nil
}

// isValidURL checks whether the given string is a syntactically valid URL
// and contains a valid scheme and host.
func isValidURL(u string) bool {
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

/*
REQUIRED FIELD: BSIV1SBOMCreator

It checks the BSI TR-03183-2
"SBOM Author / Creator" requirement.

REQUIRED FIELD.

Requirement:
  - At least one responsible author or organization
    must provide a valid contact channel (email or URL).

Accepted sources:
SPDX:
- creatorsInfo.Creator(Person/Organization).email
CDX:
- metadata.authors[].email
- metadata.manufacturer.email OR .url
- metadata.supplier.email OR metadata.supplier.contacts[].email/url
*/
func BSIV11SBOMCreator(doc sbom.Document) catalog.ProfFeatScore {

	var (
		anyFieldPresent bool
	)

	// ---- Authors ----
	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		anyFieldPresent = true

		if isValidEmail(a.GetEmail()) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator contact(email) provided via authors",
				Ignore: false,
			}
		}
	}

	// ---- Manufacturer ----
	if m := doc.Manufacturer(); m != nil {
		anyFieldPresent = true

		if isValidEmail(m.GetEmail()) || isValidURL(m.GetURL()) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator contact(email/URL) provided via manufacturer",
				Ignore: false,
			}
		}

		for _, c := range m.GetContacts() {
			if isValidEmail(c.GetEmail()) {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "SBOM creator contact(email/URL) provided via manufacturer",
					Ignore: false,
				}
			}
		}

	}

	// ---- Supplier ----
	if s := doc.Supplier(); s != nil {
		anyFieldPresent = true

		if isValidEmail(s.GetEmail()) || isValidURL(s.GetURL()) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator contact(email/URL) provided via supplier (fallback)",
				Ignore: false,
			}
		}

		for _, c := range s.GetContacts() {
			if isValidEmail(c.GetEmail()) {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "SBOM creator contact(email/URL) provided via supplier (fallback)",
					Ignore: false,
				}
			}
		}
	}

	if anyFieldPresent {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creator present but lacks valid email or URL",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM creator is missing",
		Ignore: false,
	}
}

// REQUIRED FIELD: BSIV1SBOMCreationTimestamp
//
// It checks Creation Time of SBOM
// BSI TR-03183-2 requires that the SBOM include a creation timestamp that is compliant with RFC3339 (a profile of ISO-8601).
//
// Def:
// - A date and time formatted according to the ISO 8601 standard
// - (e.g., 2025-04-25T00:42:27Z)
//
// Mappings:
// SPDX:
// - creationInfo.created
// CDX:
// - metadata.timestamp
func BSIV11SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creation timestamp is missing",
			Ignore: false,
		}
	}

	// RFC3339 covers fractional seconds
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return formulae.ScoreSBOMProfNA(
			"SBOM creation timestamp is not a valid RFC3339 (ISO-8601) timestamp.",
			false,
		)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "SBOM creation timestamp is valid and RFC3339-compliant.",
		Ignore: false,
	}
}

// component Name
func BSIV11CompName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	if total-have > 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"component name missing for %d out of %d components",
				total-have, total,
			),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "component name declared for all components",
		Ignore: false,
	}
}

// Component Version
func BSIV11CompVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	if total-have > 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"component version missing for %d out of %d components",
				total-have, total,
			),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "component version declared for all components",
		Ignore: false,
	}
}

// BSIV11CompCreator validates the BSI TR-03183-2 requirement
// for "Creator of the component".
//
// # BSI Official Definition
//
// - The SBOM must identify the creator of each component and provide
// - a valid contact channel.
//
// A valid contact channel means:
// - Email address (preferred), or
// - URL (if applicable)
//
// Motive behind the Email/URL requirement:
// - The purpose is to ensure that each component has an accountable
// - responsible entity that can be contacted. As BSI believes in automation,
// - therefore contact information must be machine-readable and actionable, which is why email or URL is required.
// - Name or phone alone is not sufficient, as they do not provide a standardized way to reach the responsible party.
//
// Accepted Fields (BSI Interpretation)
// -----------------------------------------------------------------------------
// For each component, at least ONE of the following must provide
// a valid contact (email or URL):
//
// - Authors (email)
// - Manufacturer (email or URL)
// - Supplier (email or URL)
//
// Notes:
// - Name or phone alone is NOT sufficient.
// - Presence without valid email/URL is considered invalid.
// - Only one valid contact per component is required.
//
// Component Creator Mapping:
// SPDX:
// - PackageOriginator  (preferred)
// - PackageSupplier    (fallback)
//
// CycloneDX:
// - components[].authors[].email
// - components[].manufacturer.email / .url / .contact.email
// - components[].supplier.email / .url / .contact.email
//
// What Function Says:
// - Iterates over all declared components.
// - For each component, checks Authors, Manufacturer, then Supplier.
// - Counts components with valid creator contact.
// - Returns full score if all components are valid.
// - Returns proportional score if partially valid.
// - Returns zero if only invalid or missing.
func BSIV11CompCreator(doc sbom.Document) catalog.ProfFeatScore {

	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "No components declared in SBOM",
			Ignore: false,
		}
	}

	var (
		totalValidComponentCreators  int
		totalAnyOtherCreatorsPresent int
	)

	for _, c := range comps {

		var anyCreatorFieldPresent bool
		var validCreator bool

		// ---- Authors ----
		for _, a := range c.Authors() {
			if a != nil {
				anyCreatorFieldPresent = true
			}
			if isValidEmail(a.GetEmail()) {
				validCreator = true
				break
			}
		}

		// ---- Manufacturer ----
		if !validCreator {
			if m := c.Manufacturer(); !m.IsAbsent() {

				anyCreatorFieldPresent = true

				if isValidEmail(m.GetEmail()) ||
					isValidURL(m.GetURL()) {
					validCreator = true
				}

				for _, c := range m.GetContacts() {
					if isValidEmail(c.GetEmail()) {
						validCreator = true
						break
					}
				}
			}
		}

		// ---- Supplier ----
		if !validCreator {
			if s := c.Suppliers(); !s.IsAbsent() {
				anyCreatorFieldPresent = true

				if isValidEmail(s.GetEmail()) ||
					isValidURL(s.GetURL()) {
					validCreator = true
				}

				for _, c := range s.GetContacts() {
					if isValidEmail(c.GetEmail()) {
						validCreator = true
						break
					}
				}
			}
		}

		// ---- Classification ----
		if validCreator {
			totalValidComponentCreators++
		} else if anyCreatorFieldPresent {
			totalAnyOtherCreatorsPresent++
		}
	}

	if totalValidComponentCreators == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "creator contact (email or URL) declared for all components",
			Ignore: false,
		}
	}

	if totalValidComponentCreators > 0 {
		score := float64(totalValidComponentCreators) / float64(total) * 10.0

		return catalog.ProfFeatScore{
			Score:  score,
			Desc:   fmt.Sprintf("%d/%d components provide a valid creator contact (email or URL)", totalValidComponentCreators, total),
			Ignore: false,
		}
	}

	if totalAnyOtherCreatorsPresent > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("%d/%d components have creator info, but only valid email or URL required", totalAnyOtherCreatorsPresent, total),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "creator information missing for all components",
		Ignore: false,
	}
}

// BSIV11CompLicenses validates the BSI TR-03183-2 requirement
// for "Licence(s) associated with the component".
//
// BSI Official Definition
// - Each component must declare the licence(s) associated with it
// - from the perspective of the SBOM creator.
//
// Identification rules:
// - Licences MUST use SPDX licence identifiers.
// - If not listed in SPDX → use LicenseRef-* identifiers.
// - Licence expressions must follow SPDX expression syntax.
//
// Accepted Licence Forms (BSI Interpretation):
// - Valid SPDX licence ID (e.g., MIT, Apache-2.0)
// - Valid SPDX licence expression (e.g., MIT OR Apache-2.0)
// - Valid LicenseRef-* identifier (including scancode-derived)
//
// Not accepted:
// - NONE
// - NOASSERTION
// - Empty licence values
// - Free-text names without SPDX/LicenseRef format
// - Invalid SPDX syntax (e.g., "Apache License" instead of "Apache-2.0")
//
// License Mapping:
//
// SPDX:
// - PackageLicenseConcluded
// - PackageLicenseDeclared
//
// CycloneDX:
// - components[].licenses[].license.id
// - components[].licenses[].license.expression
//
// What This Function says:
// - Iterates over all declared components.
// - Accepts licence from Concluded OR Declared fields.
// - Requires at least one valid licence per component.
// - Rejects NONE or NOASSERTION.
// - Aggregates SBOM-level score.
func BSIV11CompLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "No components found in SBOM.",
			Ignore: false,
		}
	}

	valid := 0
	presentButInvalid := 0

	for _, c := range comps {
		hasValid := false
		hasAny := false

		// Check concluded licences
		for _, l := range c.ConcludedLicenses() {
			hasAny = true

			if isAcceptableLicense(l) {
				hasValid = true
				break
			}
		}

		// Check declared licences (fallback)
		if !hasValid {
			for _, l := range c.DeclaredLicenses() {
				hasAny = true

				// id := strings.TrimSpace(l.ShortID())
				if isAcceptableLicense(l) {
					hasValid = true
					break
				}
			}
		}

		if hasValid {
			valid++
		} else if hasAny {
			presentButInvalid++
		}
	}

	if valid == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "licence information declared for all components",
			Ignore: false,
		}
	}

	if valid > 0 {
		return catalog.ProfFeatScore{
			Score:  float64(valid) / float64(total) * 10.0,
			Desc:   fmt.Sprintf("%d/%d components have valid licence info", valid, total),
			Ignore: false,
		}
	}

	if presentButInvalid > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("%d/%d components have invalid licence info", presentButInvalid, total),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "licence info is missing for all components",
		Ignore: false,
	}
}

// Acceptable licence values after parsing validation.
// Parsing already guarantees SPDX correctness.
// This only filters disallowed semantic values.
func isAcceptableLicense(s licenses.License) bool {
	id := s.ShortID()
	if id == "" {
		return false
	}

	u := strings.ToUpper(strings.TrimSpace(id))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}

	// Accpet valid SPDX licenses
	if s.Spdx() {
		return true
	}

	// Accept only properly formatted LicenseRef-*
	if s.Custom() && strings.HasPrefix(id, "LicenseRef-") {
		return true
	}

	return false
}

// BSIV11CompExecutableHash validates the BSI TR-03183-2 requirement
// for "Hash value of the executable component".
//
// BSI Official Definition:
// - The SBOM must include a cryptographically secure checksum (hash value)
// - of the executable component in its executable form (i.e., the final
// - distributable artifact), specifically using SHA-256.
//
// Accepted Hash (BSI Requirement):
// - SHA-256 ONLY
//
// Not accepted:
// - MD5
// - SHA-1
// - SHA-512
// - SHA-3
// - BLAKE*
// - Any other algorithm
//
// Even if cryptographically strong, algorithms other than SHA-256
// do NOT satisfy the BSI requirement.
//
// Checksum Mapping:
// SPDX:
// - PackageChecksum with algorithm "SHA256"
//
// CycloneDX:
// - metadata.component.hashes[].alg = "SHA-256"
// - components[].hashes[].alg = "SHA-256"
//
// What This Function says:
// - The primary (executable) component must exist.
// - It must declare a SHA-256 checksum.
// - The checksum value must be non-empty.
// - Other algorithms do NOT satisfy the requirement.
func BSIV11CompExecutableHash(doc sbom.Document) catalog.ProfFeatScore {

	primary := doc.PrimaryComp()
	if primary == nil {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "primary executable component is missing.",
			Ignore: false,
		}
	}

	for _, comp := range doc.Components() {
		if comp.GetID() != primary.GetID() {
			continue
		}

		for _, checksum := range comp.GetChecksums() {
			algo := common.NormalizeAlgoName(checksum.GetAlgo())
			value := strings.TrimSpace(checksum.GetContent())

			if algo == "SHA256" && value != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "primary executable declares a valid SHA-256 hash.",
					Ignore: false,
				}
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "primary executable component must declare a SHA-256 hash.",
		Ignore: false,
	}
}

// BSIV11CompDependencies validates the BSI TR-03183-2 requirement
// for "Dependencies on other components".
//
// BSI Definition (Simplified)
// 1. All direct dependencies of a component must be enumerated.
// 2. Dependencies must be resolved recursively (transitively).
// 3. Resolution must continue until the boundary of what is delivered.
//
// In simple terms:
// - If your software depends on something, that component must be present
// - in the SBOM. If that component depends on something else, that must also
// - be present. This continues until no further dependencies exist.
//
// The intent is to ensure complete recursive dependency closure of the
// delivered software artifact.
//
// - The dependency section must exist.
// - The primary component must declare its dependencies.
// - All dependency relationships must reference defined components.
// - All components must be reachable from the primary component.
// - No orphan or disconnected components are allowed.
func BSIV11CompDependencies(doc sbom.Document) catalog.ProfFeatScore {

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component is missing.",
			Ignore: false,
		}
	}

	rels := doc.GetRelationships()
	if len(rels) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Dependency information is missing.",
			Ignore: false,
		}
	}

	// Build component map
	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}
	componentMap[primary.GetID()] = primary.Component()

	// 1. Validate all relationships reference valid components
	for _, r := range rels {

		// exception here:
		// - From refers to SPDXRef-DOCUMENT, which is not a component but is valid for DESCRIBES relationships
		if r.GetType() == "DESCRIBES" {
			continue
		}

		// check all source relationships reference in components list
		// - if missing, that means the it's not present in the component list
		// - and this is not acceptable, because all the relationships must present in components list
		if _, ok := componentMap[r.GetFrom()]; !ok {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Dependency source references undefined component.",
				Ignore: false,
			}
		}

		// check all target relationships reference in components list
		// - if missing, that means the it's not present in the component list
		// - and this is not acceptable, because all the relationships must present in components list
		if _, ok := componentMap[r.GetTo()]; !ok {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Dependency target references undefined component.",
				Ignore: false,
			}
		}
	}

	// 2. Ensure primary declares dependencies
	outgoing := doc.GetOutgoingRelations(primary.GetID())
	if len(outgoing) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component does not declare its dependencies.",
			Ignore: false,
		}
	}

	// 3. Recursive traversal from primary
	visited := make(map[string]bool)

	var dfs func(string)
	dfs = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true

		for _, rel := range doc.GetOutgoingRelations(id) {
			if rel.GetType() == "DEPENDS_ON" {
				dfs(rel.GetTo())
			}
		}
	}

	dfs(primary.GetID())

	// 4. Ensure all reachable deps are valid components
	// (already ensured by relationship validation)

	// 5. Ensure no orphan components (strict enforcement)
	for id := range componentMap {
		if !visited[id] {
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "Some components are not reachable from the primary component.",
				Ignore: false,
			}
		}
	}

	// Fully compliant
	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "Dependencies are recursively declared and structurally complete.",
		Ignore: false,
	}
}
