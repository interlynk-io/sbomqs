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

package extractors

import (
	"fmt"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// CompWithLicenses check for concluded license
func CompWithLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyConcluded(c)
	})

	return formulae.ScoreCompFull(have, len(comps), "licenses", false)
}

// CompWithValidLicenses validates concluded licenses
func CompWithValidLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ValidationCheckConcludedLicenses(c)
	})

	return formulae.ScoreCompFull(have, len(comps), "valid SPDX licenses", false)
}

// CompWithDeclaredLicenses look for declared licenses
func CompWithDeclaredLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyDeclared(c)
	})

	return formulae.ScoreCompFull(have, len(comps), "declared licenses", false)
}

// SBOMDataLicense check for SBOM license
func SBOMDataLicense(doc sbom.Document) catalog.ComprFeatScore {
	specLicenses := doc.Spec().GetLicenses()

	if len(specLicenses) == 0 {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("data license"),
			Ignore: false,
		}
	}

	if commonV2.AreLicensesValid(specLicenses) {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(true),
			Desc:   "complete",
			Ignore: false,
		}
	}
	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   "fix data license",
		Ignore: false,
	}
}

// CompWithDeprecatedLicenses check for concluded license are not in the deprecated license list
func CompWithDeprecatedLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	// First check if any components have concluded licenses
	componentsWithConcluded := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyConcluded(c)
	})

	// If no components have concluded licenses, this check is not applicable
	if componentsWithConcluded == 0 {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "add concluded licenses first",
			Ignore: false,
		}
	}

	// Count components that HAVE deprecated licenses (problematic)
	withDeprecated := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyDeprecated(c)
	})

	// Components WITHOUT deprecated licenses (good)
	withoutDeprecated := len(comps) - withDeprecated

	var description string
	if withDeprecated == 0 {
		description = "complete"
	} else if withDeprecated == 1 {
		description = "fix 1 component"
	} else {
		description = fmt.Sprintf("fix %d components", withDeprecated)
	}

	// Score based on components WITHOUT deprecated licenses
	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(withoutDeprecated, len(comps)),
		Desc:   description,
		Ignore: false,
	}
}

// CompWithRestrictiveLicenses check for concluded license are not
// in the restrictive license list (GPL, etc)
func CompWithRestrictiveLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	// First check if any components have concluded licenses
	componentsWithConcluded := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyConcluded(c)
	})

	// If no components have concluded licenses, this check is not applicable
	if componentsWithConcluded == 0 {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "add concluded licenses first",
			Ignore: false,
		}
	}

	// Count components that HAVE restrictive licenses (problematic)
	withRestrictive := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyRestrictive(c)
	})

	// Components WITHOUT restrictive licenses (good)
	withoutRestrictive := len(comps) - withRestrictive

	var description string
	if withRestrictive == 0 {
		description = "complete"
	} else if withRestrictive == 1 {
		description = "review 1 component"
	} else {
		description = fmt.Sprintf("review %d components", withRestrictive)
	}

	// Score based on components WITHOUT restrictive licenses
	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(withoutRestrictive, len(comps)),
		Desc:   description,
		Ignore: false,
	}
}
