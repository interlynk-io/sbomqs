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

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasComponentDependencies(c)
	})

	return formulae.ScoreCompFull(have, len(comps), "dependencies", false)
}

// comp_with_declared_completeness: Completeness declaration present
func CompWithCompleteness(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		// TODO: to add this method in our sbom module, then only we can fetch it here
		// Compositions/Aggregate
		// have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		// 	return c.GetComposition() != ""
		// })
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("completeness"),
			Ignore: true,
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

// sbom_with_primary_comp: Single primary component defined
func SBOMWithPrimaryComponent(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()

	if !commonV2.HasSBOMPrimaryComponent(doc) {
		return catalog.ComprFeatScore{
			Score:  formulae.PerComponentScore(0, len(comps)),
			Desc:   "add primary component",
			Ignore: true,
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(commonV2.HasSBOMPrimaryComponent(doc)),
		Desc:   "complete",
		Ignore: false,
	}
}

// comps_with_source_code: Valid VCS URL
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

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasComponentPrimaryPackageType(c.PrimaryPurpose())
	})

	return formulae.ScoreCompFull(have, len(comps), "type", false)
}
