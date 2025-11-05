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

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

// ScoreNA score NA for comprehenssive features related to components
func ScoreCompNA() catalog.ComprFeatScore {
	return catalog.ComprFeatScore{
		Score:  PerComponentScore(0, 0),
		Desc:   NoComponentsNA(),
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

func NoComponentsNA() string           { return "N/A (no components)" }
func MissingField(field string) string { return "missing " + field }
func PresentField(field string) string { return "present " + field }
func NonSupportedSPDXField() string    { return "N/A (SPDX)" }
func UnknownSpec() string              { return "N/A (unknown spec)" }
func CompDescription(have, total int, field string) string {
	return fmt.Sprintf("%d/%d have %s", have, total, field)
}

// perComponentScore returns 10 × (have/total)
func PerComponentScore(have, total int) float64 {
	if total <= 0 {
		return 0
	}
	return 10.0 * (float64(have) / float64(total))
}

// booleanScore returns 10 if present, else 0.
func BooleanScore(present bool) float64 {
	if present {
		return 10.0
	}
	return 0.0
}

// Grade mapping (A: 9–10, B: 8–8.9, C: 7–7.9, D: 5–6.9, F: <5)
func ToGrade(interlynkScore float64) string {
	switch {
	case interlynkScore >= 9.0:
		return "A"
	case interlynkScore >= 8.0:
		return "B"
	case interlynkScore >= 7.0:
		return "C"
	case interlynkScore >= 5.0:
		return "D"
	default:
		return "F"
	}
}

// computeCategoryScore returns the weighted average of feature scores.
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

	// weighted average with renormalized weights
	var totalScoreWithWeightage float64
	for _, feature := range features {
		if feature.Ignored {
			continue
		}

		norm := feature.Weight / totalFeatureWeight
		totalScoreWithWeightage += feature.Score * norm
	}

	return totalScoreWithWeightage
}

// computeInterlynkScore returns the weighted average of category scores.
func ComputeInterlynkComprScore(catResults []api.CategoryResult) float64 {
	var totalCategoryWeight, finalScoreWithWeightage float64

	for _, catResult := range catResults {
		totalCategoryWeight += catResult.Weight
		finalScoreWithWeightage += catResult.Score * catResult.Weight
	}

	if totalCategoryWeight == 0 {
		return 0
	}
	return finalScoreWithWeightage / totalCategoryWeight
}

func ComputeInterlynkProfScore(profResults api.ProfilesResult) float64 {
	totalScore := 0.0
	for _, res := range profResults.ProfResult {
		totalScore += res.Score
	}
	return totalScore / 10.0
}
