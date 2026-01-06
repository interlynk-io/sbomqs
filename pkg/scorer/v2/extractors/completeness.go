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

// Package extractors defines each comprehenssive categories and their features evaluation in details.
// Each function in this package looks at an SBOM document
// through the lens of a single category (provenance, completeness, structural
// quality, identification, integrity, licensing, vulnerability, etc.) and
// returns a score for that feature. Higher-level code uses these helpers to
// build up category and overall scores.
package extractors

import (
	"fmt"
	"slices"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// comp_with_dependencies (component-level coverage)
// SPDX: relationships (DEPENDS_ON); CDX: component.dependencies / bom.dependencies
func CompWithDependencies(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	switch doc.Spec().GetSpecType() {

	case string(sbom.SBOMSpecSPDX):
		// SPDX: can detect dependency presence, but not completeness
		have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
			return commonV2.HasComponentDependencies(c)
		})

		return formulae.ScoreCompFullCustom(
			have,
			len(comps),
			"dependency completeness declared N/A (SPDX)",
			false,
		)

	case string(sbom.SBOMSpecCDX):

		// Only components that actually have dependencies matter
		depComps := lo.Filter(comps, func(c sbom.GetComponent, _ int) bool {
			return commonV2.HasComponentDependencies(c)
		})

		// If no components have dependencies, completeness is N/A
		if len(depComps) == 0 {
			return catalog.ComprFeatScore{
				Score:  0,
				Desc:   "no components declare dependencies",
				Ignore: false,
			}
		}

		have := lo.CountBy(depComps, func(c sbom.GetComponent) bool {
			id := c.GetID()

			for _, cst := range doc.Composition() {
				if cst.Scope() != sbom.ScopeDependencies {
					continue
				}
				if cst.Aggregate() != sbom.AggregateComplete {
					continue
				}
				if slices.Contains(cst.Dependencies(), id) {
					return true
				}
			}
			return false
		})

		desc := ""
		if have == len(depComps) {
			desc = "dependency completeness declared for all components"
		} else {
			desc = fmt.Sprintf(
				"dependency completeness declared for %d component(s)",
				have,
			)
		}

		return formulae.ScoreCompFullCustom(have, len(depComps), desc, false)
	}

	return formulae.ScoreCompNA()
}

// comp_with_declared_completeness (component-level)
func CompWithDeclaredCompleteness(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	switch doc.Spec().GetSpecType() {

	case string(sbom.SBOMSpecSPDX):
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
			id := c.GetID()

			for _, cst := range doc.Composition() {
				// global completeness applies to all components
				if cst.IsSBOMComplete() {
					return true
				}

				// scoped completeness
				if cst.Aggregate() != sbom.AggregateComplete {
					continue
				}

				switch cst.Scope() {
				case sbom.ScopeDependencies:
					return slices.Contains(cst.Dependencies(), id)
				case sbom.ScopeAssemblies:
					return slices.Contains(cst.Assemblies(), id)
				}
			}
			return false
		})

		return formulae.ScoreCompFull(have, len(comps), "declared completeness", false)
	}

	return formulae.ScoreCompNA()
}

// sbom_with_primary_comp: Single primary component defined
func SBOMWithPrimaryComponent(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()

	if !commonV2.HasSBOMPrimaryComponent(doc) {
		return catalog.ComprFeatScore{
			Score:  formulae.PerComponentScore(0, len(comps)),
			Desc:   "add primary component",
			Ignore: false,
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(commonV2.HasSBOMPrimaryComponent(doc)),
		Desc:   "complete",
		Ignore: false,
	}
}

// comps_with_source_code: Valid VCS URL for CDX and no-determinsitic field in SPDX
func CompWithSourceCode(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return commonV2.HasComponentSourceCodeURL(c.GetSourceCodeURL())
	})

	return formulae.ScoreCompFull(have, len(comps), "source URIs", false)
}

// comp_with_supplier
func CompWithSupplier(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.IsSupplierEntity(c.Suppliers())
	})

	return formulae.ScoreCompFull(have, len(comps), "suppliers", false)
}

// comp_with_primary_purpose
func CompWithPackagePurpose(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	supported := sbom.SupportedPrimaryPurpose((doc.Spec().GetSpecType()))

	var validCount, invalidCount, missCount int

	for _, c := range comps {
		purpose := strings.TrimSpace(c.PrimaryPurpose())

		switch {
		case purpose == "":
			missCount++

		case lo.Contains(supported, strings.ToLower(purpose)):
			validCount++

		default:
			invalidCount++
		}
	}

	desc := "complete"

	switch {
	case invalidCount > 0:
		desc = fmt.Sprintf(
			"correct for %d %s",
			invalidCount,
			componentWord(invalidCount),
		)
		if missCount > 0 {
			desc += " (others missing)"
		}

	case missCount > 0:
		desc = fmt.Sprintf(
			"add to %d %s",
			missCount,
			componentWord(missCount),
		)
	}

	return formulae.ScoreCompFullCustom(validCount, len(comps), desc, false)
}

func componentWord(n int) string {
	if n == 1 {
		return "component"
	}
	return "components"
}

// sbom_with_declared_completeness
func SBOMWithDeclaredCompleteness(doc sbom.Document) catalog.ComprFeatScore {
	switch doc.Spec().GetSpecType() {

	case string(sbom.SBOMSpecSPDX):
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: false,
		}

	case string(sbom.SBOMSpecCDX):
		if DeclaresSBOMComplete(doc) {
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(true),
				Desc:   "SBOM completeness declared",
				Ignore: false,
			}
		}

		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "SBOM completeness not declared",
			Ignore: false,
		}
	}

	return formulae.ScoreCompNA()
}

// DeclaresSBOMComplete returns true if the SBOM
// explicitly declares global completeness.
func DeclaresSBOMComplete(doc sbom.Document) bool {
	for _, c := range doc.Composition() {
		if c.IsSBOMComplete() {
			return true
		}
	}
	return false
}
