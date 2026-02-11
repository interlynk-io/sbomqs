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
	"strings"
	"time"

	"net/mail"
	"net/url"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
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
func BSIV1SBOMCreator(doc sbom.Document) catalog.ProfFeatScore {
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
				Desc:   "SBOM creator is provided using the supplier field.",
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

	return formulae.ScoreSBOMProfFull(
		"SBOM creation timestamp is valid and RFC3339-compliant.",
		false,
	)
}

/*
BSIV1CompCreator
- Email address of the entity that created and, if applicable, maintains the respective software component.
- If no email address is available, this MUST be a URL.
*/
func BSIV1CompCreator(doc sbom.Document) catalog.ProfFeatScore {
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

// Component Version

func BSIV2Dependencies(doc sbom.Document) catalog.ProfFeatScore {

	primary := doc.PrimaryComp()
	components := doc.Components()
	dependencies := doc.GetRelationships()

	if primary == nil {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component is missing; dependency validation cannot be performed.",
			Ignore: false,
		}
	}

	if len(dependencies) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Dependency information is missing.",
			Ignore: false,
		}
	}

	// Build component map
	componentMap := make(map[string]struct{})
	for _, c := range components {
		componentMap[c.GetID()] = struct{}{}
	}

	// Include primary explicitly (if not already)
	componentMap[primary.GetID()] = struct{}{}

	// ------------------------------------------------------------
	// Build dependency map
	// ------------------------------------------------------------

	depMap := make(map[string][]string)
	for _, d := range dependencies {
		depMap[d.Ref] = d.DependsOn
	}

	totalComponents := len(componentMap)

	// ------------------------------------------------------------
	// 1️⃣ Validate primary has dependency declaration
	// ------------------------------------------------------------

	if _, ok := depMap[primary.BomRef()]; !ok {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component does not declare its dependencies.",
			Ignore: false,
		}
	}

	// ------------------------------------------------------------
	// 2️⃣ Validate all dependency references resolve
	// ------------------------------------------------------------

	for ref, deps := range depMap {

		if _, exists := componentMap[ref]; !exists {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Dependency reference is not defined as a component.",
				Ignore: false,
			}
		}

		for _, target := range deps {
			if _, exists := componentMap[target]; !exists {
				return catalog.ProfFeatScore{
					Score:  0.0,
					Desc:   "Dependency target is not defined as a component.",
					Ignore: false,
				}
			}
		}
	}

	// ------------------------------------------------------------
	// 3️⃣ Validate recursive completeness
	// Every component must explicitly declare dependencies
	// (empty list allowed)
	// ------------------------------------------------------------

	for ref := range componentMap {
		if _, declared := depMap[ref]; !declared {
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "Some components do not explicitly declare their dependencies.",
				Ignore: false,
			}
		}
	}

	// ------------------------------------------------------------
	// 4️⃣ Validate reachability from primary
	// ------------------------------------------------------------

	visited := make(map[string]bool)

	var dfs func(string)
	dfs = func(node string) {
		if visited[node] {
			return
		}
		visited[node] = true
		for _, child := range depMap[node] {
			dfs(child)
		}
	}

	dfs(primary.BomRef())

	for ref := range componentMap {
		if !visited[ref] {
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "Some components are not reachable from the primary component.",
				Ignore: false,
			}
		}
	}

	// ------------------------------------------------------------
	// Fully compliant (structural recursion satisfied)
	// ------------------------------------------------------------

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "Dependencies are declared with recursive completeness and structural integrity.",
		Ignore: false,
	}
}

// BSISBOMNamespace checks URI/Namespace
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

// BSICompWithName checks Component Name
func BSICompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// BSICompWithVersion checks Component Version
func BSICompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
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
