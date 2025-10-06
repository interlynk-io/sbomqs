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

package v2

// perComponentScore returns 10 × (have/total)
func perComponentScore(have, total int) float64 {
	if total <= 0 {
		return 0
	}
	return 10.0 * (float64(have) / float64(total))
}

// booleanScore returns 10 if present, else 0.
func booleanScore(present bool) float64 {
	if present {
		return 10.0
	}
	return 0.0
}

// Grade mapping (A: 9–10, B: 8–8.9, C: 7–7.9, D: 5–6.9, F: <5)
func toGrade(interlynkScore float64) string {
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
func computeCategoryScore(features []FeatureResult) float64 {
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
func computeInterlynkScore(catResults []CategoryResult) float64 {
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
