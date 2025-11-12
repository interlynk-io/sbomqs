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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// CompWithLicenses check for concluded license
func CompWithLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyConcluded(c)
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
		return validationCheckConcludedLicenses(c)
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
		return componentHasAnyDeclared(c)
	})

	return formulae.ScoreCompFull(have, len(comps), "declared licenses", false)
}

// SBOMDataLicense check for SBOM license
func SBOMDataLicense(doc sbom.Document) catalog.ComprFeatScore {
	specLicenses := doc.Spec().GetLicenses()

	if len(specLicenses) == 0 {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "no data license",
			Ignore: false,
		}
	}

	if areLicensesValid(specLicenses) {
		l := strings.TrimSpace(specLicenses[0].ShortID())
		if l == "" {
			l = strings.TrimSpace(specLicenses[0].Name())
		}
		if l == "" {
			l = "data license present"
		}
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(true),
			Desc:   l,
			Ignore: false,
		}
	}
	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   "invalid data license",
		Ignore: false,
	}
}

// CompWithDeprecatedLicenses check for concluded license are not in the deprecated license list
func CompWithDeprecatedLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyDeprecated(c)
	})

	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   fmt.Sprintf("%d deprecated", have),
		Ignore: false,
	}
}

// CompWithNoDeprecatedLicenses check for concluded license are not
// in the restrictive license list (GPL, etc)
func CompWithRestrictiveLicenses(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyRestrictive(c)
	})

	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   fmt.Sprintf("%d restrictive", have),
		Ignore: false,
	}
}
