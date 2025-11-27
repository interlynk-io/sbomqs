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

package formulae

import (
	"fmt"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
)

// ScoreNA score NA for comprehenssive features related to components
func ScoreCompNA() catalog.ComprFeatScore {
	return catalog.ComprFeatScore{
		Score:  PerComponentScore(0, 0),
		Desc:   NoComponentsNA(),
		Ignore: true,
	}
}

// ScoreNA score NA for comprehenssive features related to components
func ScoreCompNAA() catalog.ComprFeatScore {
	return catalog.ComprFeatScore{
		Score:  PerComponentScore(0, 0),
		Desc:   NoComponentsNAA(),
		Ignore: true,
	}
}

// ScoreCompFull score for comprehenssive features related to components
func ScoreCompFull(have, comps int, field string, ignore bool) catalog.ComprFeatScore {
	return catalog.ComprFeatScore{
		Score:  PerComponentScore(have, comps),
		Desc:   CompDescription(have, comps, field),
		Ignore: ignore,
	}
}

// ScoreProfNA score NA for profile features related to components
func ScoreProfNA(ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  PerComponentScore(0, 0),
		Desc:   NoComponentsNA(),
		Ignore: ignore,
	}
}

// ScoreProfNA score for profile features related to components
func ScoreProfFull(have, comps int, feat string, ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  PerComponentScore(have, comps),
		Desc:   CompDescription(have, comps, feat),
		Ignore: ignore,
	}
}

// ScoreProfNA score NA for profile features related to sbom
func ScoreSBOMProfNA(desc string, ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  BooleanScore(false),
		Desc:   desc,
		Ignore: ignore,
	}
}

// ScoreProfNA score full for profile features related to sbom
func ScoreSBOMProfFull(field string, ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  BooleanScore(true),
		Desc:   PresentField(field),
		Ignore: ignore,
	}
}

// ScoreSBOMProfMissingNA score NA for profile features related to sbom
func ScoreSBOMProfMissingNA(field string, ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  BooleanScore(false),
		Desc:   MissingField(field),
		Ignore: ignore,
	}
}

// ScoreSBOMProfMissingNA score NA for profile features related to sbom
func ScoreSBOMProfUnknownNA(field string, ignore bool) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  BooleanScore(false),
		Desc:   UnknownSpec(),
		Ignore: ignore,
	}
}
func NoComponentsNAA() string          { return "N/A" }
func NoComponentsNA() string           { return "N/A (no components)" }
func MissingField(field string) string { return "add " + field }
func PresentField(field string) string { return "complete" }
func NonSupportedSPDXField() string    { return "N/A (SPDX)" }
func UnknownSpec() string              { return "N/A (unknown spec)" }

// CompDescription returns an action-oriented description for component features
func CompDescription(have, total int, field string) string {
	if have == total {
		return "complete"
	}
	missing := total - have
	if missing == 1 {
		return "add to 1 component"
	}
	return fmt.Sprintf("add to %d components", missing)
}

// PerComponentScore returns 10 × (have/total)
// If not all components have the feature, caps at 9.9 to avoid false 10.0 display
func PerComponentScore(have, total int) float64 {
	if total <= 0 {
		return 0
	}
	score := 10.0 * (float64(have) / float64(total))
	// Cap at 9.9 if not complete to avoid rounding to 10.0
	if have < total && score > 9.9 {
		return 9.9
	}
	return score
}

// booleanScore returns 10 if present, else 0.
func BooleanScore(present bool) float64 {
	if present {
		return 10.0
	}
	return 0.0
}

// Grade mapping (A: 9–10, B: 8–8.9, C: 7–7.9, D: 5–6.9, F: <5)
func ToGrade(score float64) string {
	switch {
	case score >= 9.0:
		return "A"
	case score >= 8.0:
		return "B"
	case score >= 7.0:
		return "C"
	case score >= 5.0:
		return "D"
	default:
		return "F"
	}
}

/*
		 ComputeCategoryScore calculates the category-level score using a weighted
		 average of all non-ignored feature scores.

		 category_score = Σ(score_i * (weight_i / totalFeatureWeight))
	                    = (Σ(score_i * weight_i)) / totalFeatureWeight

		 Behavior:
		  1. totalFeatureWeight = Sums the weights of all features where Ignored == false.
		  2. If no valid weights remain, returns 0.
		  3. Renormalizes each feature’s weight (weight_i / totalFeatureWeight).
		  4. Computes the weighted average: Σ(score_i * normalizedWeight_i).
*/
func ComputeCategoryScore(features []api.FeatureResult) float64 {
	var totalFeatureWeight float64
	for _, feature := range features {
		if !feature.Ignored {
			totalFeatureWeight += feature.Weight
		}
	}

	if totalFeatureWeight <= 0 {
		return 0
	}

	var weightedScore float64

	for _, feature := range features {
		if feature.Ignored {
			continue
		}

		score_i := feature.Score
		weight_i := feature.Weight

		normalizedWeight_i := weight_i / totalFeatureWeight
		weightedScore += score_i * normalizedWeight_i
	}

	return weightedScore
}

/*
ComputeInterlynkComprScore computes the final Interlynk SBOM Quality score by
taking a weighted average of all category scores.

Skips the "compinfo" category, which represents Component Quality

interlynk_score = Σ(category_score × category_weight) / Σ(category_weight)

where, totalCategoriesScore = Σ(category_score × category_weight)
and, totalCategoriesWeight = Σ(category_weight)
*/
func ComputeInterlynkComprScore(catResults []api.CategoryResult) float64 {
	var totalCategoriesWeight, totalCategoriesScore float64

	for _, catResult := range catResults {

		// Skip component qaulity informational category
		if catResult.Key == "compinfo" {
			continue
		}

		totalCategoriesWeight += catResult.Weight
		totalCategoriesScore += catResult.Score * catResult.Weight
	}

	if totalCategoriesWeight == 0 {
		return 0
	}
	return totalCategoriesScore / totalCategoriesWeight
}

func ComputeInterlynkProfScore(result api.ProfileResult) float64 {
	totalScore := 0.0

	var total int
	for _, res := range result.Items {
		// Only include required fields in the score calculation
		if res.Required {
			total++
			totalScore += res.Score
		}
	}
	if total == 0 {
		return 0.0
	}
	return totalScore / float64(total)
}
