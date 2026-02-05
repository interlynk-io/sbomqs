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
	"slices"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// // Automation Support
// func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMAutomationSpec(doc)
// }

// NTIACompWithSupplier
// NTIA says:
// - This refers to the **authority responsible for the component’s identity**, not manufacturing or legal ownership.
//
// Mappings:
// - For SPDX: PackageSupplier, PackageOriginator
// - For CycloneDX: Component Supplier, Component Manufacturer
func NTIACompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
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
		haveSupplier     int
		haveManufacturer int
		haveAny          int
	)

	for _, c := range comps {

		// --- 1. Prefer supplier (SPDX + CycloneDX) ---
		supplier := c.Suppliers()
		if supplier != nil {
			hasName := strings.TrimSpace(supplier.GetName()) != ""
			hasURL := strings.TrimSpace(supplier.GetURL()) != ""
			hasEmail := strings.TrimSpace(supplier.GetEmail()) != ""

			if hasName || hasURL || hasEmail {
				haveSupplier++
				haveAny++
				continue // if supplier is present, skip manufacturer check
			}
		}

		manufacturer := c.Manufacturer()
		if manufacturer != nil {
			hasName := strings.TrimSpace(manufacturer.GetName()) != ""
			hasURL := strings.TrimSpace(manufacturer.GetURL()) != ""
			hasEmail := strings.TrimSpace(manufacturer.GetEmail()) != ""

			if hasName || hasURL || hasEmail {
				haveManufacturer++
				haveAny++
				continue
			}
		}
	}

	// --- 3. Build description ---
	desc := fmt.Sprintf(
		"supplier or manufacturer information missing for all %d components",
		total,
	)

	if haveAny == total {
		if haveSupplier == total {
			desc = "supplier information declared for all components"
		} else if haveSupplier > 0 {
			desc = fmt.Sprintf(
				"supplier information declared for %d components; manufacturer used as fallback for %d components",
				haveSupplier, haveManufacturer,
			)
		} else {
			desc = "manufacturer information declared for all components (supplier not present)"
		}
	} else if haveAny > 0 {
		desc = fmt.Sprintf(
			"supplier or manufacturer information declared for %d of %d components",
			haveAny, total,
		)
	}

	return catalog.ProfFeatScore{
		Score:  float64(haveAny) / float64(total) * 10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIACompWithName check for component with name
// NTIA says:
// - Name assigned to the component by the supplier
//
// Mappings:
// - For SPDX: PackageName
// - For CycloneDX: Component Name
func NTIACompWithName(doc sbom.Document) catalog.ProfFeatScore {
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

	var desc string

	if have == total {
		desc = "name declared for all components"
	} else {
		desc = fmt.Sprintf("name declared for %d of %d components", have, total)
	}

	return catalog.ProfFeatScore{
		Score:  float64(have) / float64(total) * 10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIACompWithVersion check for Component with Version
// NTIA says:
// - Version identifier used to distinguish a specific release.
//
// Mappings:
// - For SPDX: PackageVersion
// - For CycloneDX: Component Version
func NTIACompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	var desc string

	if have == total {
		desc = "version declared for all components"
	} else {
		desc = fmt.Sprintf("version declared for %d of %d components", have, total)
	}

	return catalog.ProfFeatScore{
		Score:  float64(have) / float64(total) * 10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIACompWithUniqID checks Component Other Identifiers such as PURL/CPE
// NTIA says:
// - At least one additional identifier if available (e.g., CPE, PURL, SWID).
//
// Mappings:
// - For SPDX: PackageExternalRefs (PURL), PackageCPEs
// - For CycloneDX: Component External References (PURL), Component CPEs
// NTIACompWithUniqID checks Component Other Identifiers such as PURL/CPE
// NTIA says:
// - At least one additional identifier if available (e.g., CPE, PURL, SWID).
//
// Mappings:
// - For SPDX: PackageExternalRefs (PURL), PackageCPEs
// - For CycloneDX: Component External References (PURL), Component CPEs
func NTIACompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
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
		have     int
		purlSeen bool
		cpeSeen  bool
	)

	for _, c := range comps {
		t := detectPURLOrCPEsUniqueIDs(c)

		if t.purl || t.cpe {
			have++
		}

		purlSeen = purlSeen || t.purl
		cpeSeen = cpeSeen || t.cpe
	}

	// Build identifier kind list (informational only)
	var kinds []string
	if purlSeen {
		kinds = append(kinds, "PURL")
	}
	if cpeSeen {
		kinds = append(kinds, "CPE")
	}

	// Description
	desc := fmt.Sprintf(
		"unique identifier missing for all %d components",
		total,
	)

	if have == total {
		if len(kinds) > 0 {
			desc = fmt.Sprintf(
				"unique identifier declared for all components (%s)",
				strings.Join(kinds, ", "),
			)
		} else {
			desc = "unique identifier declared for all components"
		}
	} else if have > 0 {
		if len(kinds) > 0 {
			desc = fmt.Sprintf(
				"unique identifier declared for %d of %d components (%s)",
				have, total, strings.Join(kinds, ", "),
			)
		} else {
			desc = fmt.Sprintf(
				"unique identifier declared for %d of %d components",
				have, total,
			)
		}
	}

	return catalog.ProfFeatScore{
		Score:  float64(have) / float64(total) * 10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// checkUniqueID checks for PURL/CPE
func detectPURLOrCPEsUniqueIDs(c sbom.GetComponent) uniqIDTypes {
	var t uniqIDTypes

	for _, p := range c.GetPurls() {
		if strings.TrimSpace(string(p)) != "" {
			t.purl = true
		}
	}
	for _, cpe := range c.GetCpes() {
		if strings.TrimSpace(string(cpe)) != "" {
			t.cpe = true
		}
	}
	return t
}

// NTIASBOMWithDependencyRelationships
//
// NTIA says:
// - At minimum, top-level dependencies or explicit completeness declarations must be present.
//
// NTIA requires that an SBOM declare the upstream dependency relationships
// of the *primary (top-level) component*.
// - At a minimum, the SBOM must list the primary component's direct dependencies.
// - or decalrer completeness if no dependencies exist.
//
// Mappings:
// - For SPDX: Relationship with type "DEPENDS_ON" from primary component
// - For CycloneDX: Component dependencies from primary component
func NTIASBOMWithDependencyRelationships(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")
	}

	// 1. Get direct dependencies of the primary component
	// if the primary component declares at least one direct dependency,
	// NTIA dependency requirement is satisfied
	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(directDeps) > 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   fmt.Sprintf("primary component declares %d direct (top-level) dependencies", len(directDeps)),
			Ignore: false,
		}
	}

	// 2. no direct dependencies --> check relationship completeness
	for _, c := range doc.Composition() {

		if c.Scope() != sbom.ScopeDependencies {
			continue
		}

		// Composition applies to primary component
		if !slices.Contains(c.Dependencies(), primary.GetID()) {
			continue
		}

		switch c.Aggregate() {
		case sbom.AggregateComplete:
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "primary component declares no direct dependencies and explicitly states relationship completeness (complete)",
				Ignore: false,
			}

		case sbom.AggregateUnknown:
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "primary component declares no direct dependencies and states relationship completeness as unknown",
				Ignore: false,
			}

		case sbom.AggregateIncomplete:
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "primary component declares no direct dependencies and states relationship completeness as incomplete",
				Ignore: false,
			}
		}
	}

	// 3. No dependencies and no completeness declaration
	// Default interpretation per NTIA: missing
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "primary component declares no direct dependencies and does not declare relationship completeness",
		Ignore: false,
	}
}

// NTIASBOMWithAuthors
// NTIA says
// - Author reflects the source of the metadata, which could come from the creator of the software being described in the SBOM, the upstream component supplier, or some third-party analysis tool.
//
// Mappings:
// - For SPDX: CreationInfo.Creators of type "Person" or "Organization" or "Tool"
// - For CycloneDX: metadata.authors(preferred) or metadata.tools(allowed) or metadata.supplier(fallback) or metadata.manufacturer(fallback)
func NTIASBOMWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	authors := doc.Authors()

	for _, author := range authors {
		name := strings.TrimSpace(author.GetName())
		email := strings.TrimSpace(author.GetEmail())

		if name != "" || email != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM author declared explicitly",
				Ignore: false,
			}
		}
	}

	for _, tool := range doc.Tools() {
		name := strings.TrimSpace(tool.GetName())
		version := strings.TrimSpace(tool.GetVersion())

		if name != "" && version != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM author inferred from SBOM generation tool",
				Ignore: false,
			}
		}

		if name != "" {
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "SBOM author inferred from SBOM generation tool (name only)",
				Ignore: false,
			}
		}

		if version != "" {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "SBOM author inferred from SBOM generation tool (version only)",
				Ignore: false,
			}
		}
	}

	// 3. Supplier fallback
	supplier := doc.Supplier()
	if supplier != nil {
		name := strings.TrimSpace(supplier.GetName())
		email := strings.TrimSpace(supplier.GetEmail())
		url := strings.TrimSpace(supplier.GetURL())

		if name != "" || email != "" || url != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM author inferred from supplier (fallback)",
				Ignore: false,
			}
		}
	}

	// 4. Manufacturer fallback
	manufacturer := doc.Manufacturer()
	if manufacturer != nil {
		name := strings.TrimSpace(manufacturer.GetName())
		email := strings.TrimSpace(manufacturer.GetEmail())
		url := strings.TrimSpace(manufacturer.GetURL())

		if name != "" || email != "" || url != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM author inferred from manufacturer (fallback)",
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM author information missing",
		Ignore: false,
	}
}

// NTIASBOMWithTimeStamp
func NTIASBOMWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())

	if ts == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creation timestamp missing",
			Ignore: false,
		}
	}

	// Accept RFC3339 or RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "SBOM creation timestamp present but not RFC3339 compliant",
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "SBOM creation timestamp declared",
		Ignore: false,
	}
}

// // NTIA Optional Fields - These don't impact overall scoring but show field coverage

// // Component Hash (SHOULD)
// func NTIACompHash(doc sbom.Document) catalog.ProfFeatScore {
// 	return CompHash(doc)
// }

// // SBOM Lifecycle (SHOULD)
// func NTIASBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
// 	lifecycles := doc.Lifecycles()
// 	if len(lifecycles) > 0 {
// 		return catalog.ProfFeatScore{
// 			Score: 10.0,
// 			Desc:  "complete",
// 		}
// 	}
// 	return catalog.ProfFeatScore{
// 		Score: 0.0,
// 		Desc:  "add lifecycle phase",
// 	}
// }

// // Component License (SHOULD)
// func NTIACompLicense(doc sbom.Document) catalog.ProfFeatScore {
// 	comps := doc.Components()
// 	if len(comps) == 0 {
// 		return catalog.ProfFeatScore{
// 			Score: 0.0,
// 			Desc:  formulae.NoComponentsNA(),
// 		}
// 	}

// 	have := 0
// 	for _, c := range comps {
// 		licenses := c.GetLicenses()
// 		if len(licenses) > 0 {
// 			have++
// 		}
// 	}

// 	total := len(comps)
// 	score := (float64(have) / float64(total)) * 10.0

// 	return catalog.ProfFeatScore{
// 		Score: score,
// 		Desc:  formulae.CompDescription(have, total),
// 	}
// }
