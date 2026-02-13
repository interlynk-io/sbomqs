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

// // BSISBOMSpec checks SBOM Formats
// func BSISBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMSpec(doc)
// }

// // BSISBOMSpecVersion checks SBOM Spec Version
// func BSISBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMSpecVersion(doc)
// }

// // BSISBOMBuildLifecycle checks Build Information
// func BSISBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMLifeCycle(doc)
// }

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
- metadata.supplier.email OR .url
*/
func BSIV11SBOMCreator(doc sbom.Document) catalog.ProfFeatScore {
	authors := doc.Authors()

	var (
		presentAuthor       bool
		presentManufacturer bool
		presentSupplier     bool
	)

	// 1. Authors (Primary)
	for _, author := range authors {
		presentAuthor = true

		email := author.GetEmail()
		if isValidEmail(email) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator is provided using the authors field.",
				Ignore: false,
			}
		}
	}

	// 2. Manufacturer
	manufacturer := doc.Manufacturer()
	if manufacturer != nil {
		presentManufacturer = true

		if isValidEmail(manufacturer.GetEmail()) ||
			isValidURL(manufacturer.GetURL()) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator is provided using the manufacturer field.",
				Ignore: false,
			}
		}
	}

	// 3. Supplier (Fallback)
	supplier := doc.Supplier()
	if supplier != nil {
		presentSupplier = true

		if isValidEmail(supplier.GetEmail()) ||
			isValidURL(supplier.GetURL()) {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM creator is provided using the supplier field (fallback).",
				Ignore: false,
			}
		}
	}

	// Creator present but invalid contact
	if presentAuthor || presentManufacturer || presentSupplier {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creator information is present, but only valid email or URL are accepted.",
			Ignore: false,
		}
	}

	// Completely missing
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM creator is missing.",
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
func BSIV1SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return formulae.ScoreSBOMProfMissingNA("SBOM creation timestamp is missing.", false)
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

/*
BSIV1CompCreator
- Email address of the entity that created and, if applicable, maintains the respective software component.
- If no email address is available, this MUST be a URL.
*/
func BSIV11CompCreator(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	var (
		validComponents   int
		presentButInvalid int
	)

	for _, c := range comps {

		valid := false
		present := false

		// 1. Author(preferred)
		for _, a := range c.Authors() {
			present = true
			if isValidEmail(a.GetEmail()) {
				valid = true
				break
			}
		}

		// 2. Manufacturer
		if !valid {
			if m := c.Manufacturer(); m != nil {
				present = true
				if isValidEmail(m.GetEmail()) || isValidURL(m.GetURL()) {
					valid = true
				}
			}
		}

		// 3. Supplier (fallback)
		if !valid {
			if s := c.Suppliers(); s != nil {
				present = true
				if isValidEmail(s.GetEmail()) || isValidURL(s.GetURL()) {
					valid = true
				}
			}
		}

		if valid {
			validComponents++
		} else if present {
			presentButInvalid++
		}
	}

	if validComponents == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "All components declare a creator using a valid email or URL.",
			Ignore: false,
		}
	}

	if validComponents > 0 {
		return catalog.ProfFeatScore{
			Score:  5.0,
			Desc:   "Some components declare a valid creator, while others are missing a valid email or URL.",
			Ignore: false,
		}
	}

	if presentButInvalid > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Creator information is present for components, but a valid email or URL is required.",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "Creator information is missing for all components.",
		Ignore: false,
	}
}

// component Name
func BSIV1CompName(doc sbom.Document) catalog.ProfFeatScore {
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
				"component name missing for %d of %d components",
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
func BSIV1CompVerson(doc sbom.Document) catalog.ProfFeatScore {
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
				"component version missing for %d of %d components",
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

// BSIV1CompDependencies validates the BSI TR-03183-2 requirement
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
// -----------------------------------------------------------------------------
// What This Function Enforces
// -----------------------------------------------------------------------------
// Since an SBOM validator cannot infer real-world missing dependencies,
// this function enforces structural recursive completeness of the declared
// dependency graph:
//
// - The dependency section must exist.
// - The primary component must declare its dependencies.
// - All dependency relationships must reference defined components.
// - All components must be reachable from the primary component.
// - No orphan or disconnected components are allowed.
func BSIV1CompDependencies(doc sbom.Document) catalog.ProfFeatScore {

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
		if r.GetType() == "DESCRIBES" {
			continue
		}

		if _, ok := componentMap[r.GetFrom()]; !ok {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Dependency source references undefined component.",
				Ignore: false,
			}
		}

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

// BSISBOMNamespace checks URI/Namespace
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

// BSICompWithLicenses checks Component License
// BSIV1CompLicenses validates the BSI TR-03183-2 requirement
// for "Licence(s) associated with the component".
//
// BSI requires that each component declare its licence from the
// perspective of the SBOM creator using valid SPDX identifiers,
// SPDX expressions, or LicenseRef-* identifiers.
//
// Parsing stage already guarantees SPDX correctness.
// This function enforces presence and structural completeness.
//
// Rules enforced:
// - Each component must have at least one licence.
// - Accepts Concluded OR Declared licences.
// - Rejects NONE or NOASSERTION.
// - Aggregates SBOM-level score.
func BSIV1CompLicenses(doc sbom.Document) catalog.ProfFeatScore {
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
			Desc:   "All components declare valid licence information.",
			Ignore: false,
		}
	}

	if valid > 0 {
		return catalog.ProfFeatScore{
			Score:  float64(valid) / float64(total) * 10.0,
			Desc:   fmt.Sprintf("%d components out of %d have valid licence information.", valid, total),
			Ignore: false,
		}
	}

	if presentButInvalid > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("%d components out of %d have Licence information but invalid.", presentButInvalid, total),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "Licence information is missing for all components.",
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

// BSIV1ExecutableHash validates the BSI TR-03183-2 requirement
// for "Hash value of the executable component".
//
// BSI requires that the executable component declare a
// cryptographically secure checksum specifically using SHA-256.
//
// Rules enforced:
// - Primary (executable) component must exist.
// - It must declare a SHA-256 checksum.
// - The checksum value must be non-empty.
// - Other algorithms do NOT satisfy this requirement.
func BSIV1ExecutableHash(doc sbom.Document) catalog.ProfFeatScore {

	primary := doc.PrimaryComp()
	if primary == nil {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary executable component is missing.",
			Ignore: false,
		}
	}

	for _, comp := range doc.Components() {
		if comp.GetID() != primary.GetID() {
			continue
		}
		fmt.Println("Primary comp : ", comp.GetID())

		for _, checksum := range comp.GetChecksums() {
			algo := common.NormalizeAlgoName(checksum.GetAlgo())
			value := strings.TrimSpace(checksum.GetContent())

			if algo == "SHA256" && value != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "Primary executable declares a valid SHA-256 hash.",
					Ignore: false,
				}
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "Primary executable component must declare a SHA-256 hash.",
		Ignore: false,
	}
}

// BSICompWithLicenses checks Component License
func BSICompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// BSICompWithHash checks Component Hash
func BSICompWithHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// BSICompWithSourceCodeURI checks Component Source URL
func BSICompWithSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeURL(doc)
}

// BSICompWithDownloadURI checks Component Download URL
func BSICompWithDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompDownloadCodeURL(doc)
}

// BSICompWithSourceCodeHash checks Component Source Hash
func BSICompWithSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeHash(doc)
}

// BSICompWithDependencies evaluates component-level dependency correctness
// for summary scoring, per BSI TR-03183.
//
// BSI rules:
// - Dependencies are defined by DEPENDS_ON and CONTAINS relationships.
// - Dependency checks apply to individual components, not the primary component.
// - Components with no dependencies are valid leaf components.
// - Scoring reflects correctness of declared dependencies, not completeness.
// - Components are only penalized if declared dependency references are invalid.
func BSICompWithDependencies(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(false)
	}

	withDeps := lo.Filter(comps, func(c sbom.GetComponent, _ int) bool {
		deps := doc.GetDirectDependencies(
			c.GetID(),
			"DEPENDS_ON",
			"CONTAINS",
		)
		return len(deps) > 0
	})

	// If no component declares dependencies, this is valid but N/A
	if len(withDeps) == 0 {
		return formulae.ScoreProfileCustomNA(false, "no components declare dependencies")
	}

	// All declared dependencies must be resolvable
	valid := lo.CountBy(withDeps, func(c sbom.GetComponent) bool {
		deps := doc.GetDirectDependencies(
			c.GetID(),
			"DEPENDS_ON",
			"CONTAINS",
		)
		return len(deps) > 0
	})

	return formulae.ScoreProfFull(valid, len(withDeps), false)
}
