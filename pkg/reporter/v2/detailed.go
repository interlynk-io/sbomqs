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

import (
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/olekukonko/tablewriter"
)

type proTable struct {
	profilesDoc    [][]string
	profilesHeader []string
	messages       string
	result         api.ProfileResult // the underlying result, for summary display
}

func (r *Reporter) detailedReport() {
	form := "https://forms.gle/anFSspwrk7uSfD7Q6"
	hasNonFeatureResults := false

	for _, res := range r.Results {
		// Check for feature-only scoring mode
		if res.ProfileContext != "" && res.Comprehensive != nil && len(res.Comprehensive.CatResult) > 0 && res.Comprehensive.CatResult[0].Key == "feature_scoring" {
			r.renderFeatureScoreDetailed(res)
			fmt.Println()
			continue
		}

		hasNonFeatureResults = true

		// buffers for table rows
		outDoc := [][]string{}     // detailed comprehensive rows
		profOutDoc := [][]string{} // profile summary rows

		var pros []proTable

		header := []string{}
		profHeader := []string{}

		if res.Comprehensive != nil && res.Profiles != nil {
			fmt.Printf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s\n\n", res.Comprehensive.InterlynkScore, res.Comprehensive.Grade, res.Meta.NumComponents, EngineVersion, res.Meta.Filename)

			profHeader = []string{"PROFILE", "SCORE", "GRADE"}

			for _, proResult := range res.Profiles.ProfResult {
				l := []string{proResult.Name, fmt.Sprintf("%.1f/10.0", proResult.Score), proResult.Grade}
				profOutDoc = append(profOutDoc, l)
			}

			totalCatWeight := calculateTotalCategoryWeight(res.Comprehensive.CatResult)
			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range res.Comprehensive.CatResult {
				isCompInfo := cat.Key == "compinfo"
				catNameWithWeight := formatCategoryWithWeight(cat.Name, cat.Weight, totalCatWeight, isCompInfo)
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					featNameWithWeight := formatFeatureWithWeight(feat.Key, feat.OrGroup, cat.Weight, feat.Weight, totalCatWeight, isCompInfo)
					l := []string{catNameWithWeight, featNameWithWeight, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}

				if cat.Key == "compinfo" {
					l := []string{catNameWithWeight, "NOTE: Register Interest for Component Analysis", "", "https://forms.gle/WVoB3DrX9NKnzfhV8"}
					outDoc = append(outDoc, l)
				}
			}

		} else if res.Comprehensive != nil {
			fmt.Printf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s\n", res.Comprehensive.InterlynkScore, res.Comprehensive.Grade, res.Meta.NumComponents, EngineVersion, res.Meta.Filename)

			totalCatWeight := calculateTotalCategoryWeight(res.Comprehensive.CatResult)
			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range res.Comprehensive.CatResult {
				isCompInfo := cat.Key == "compinfo"
				catNameWithWeight := formatCategoryWithWeight(cat.Name, cat.Weight, totalCatWeight, isCompInfo)
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					featNameWithWeight := formatFeatureWithWeight(feat.Key, feat.OrGroup, cat.Weight, feat.Weight, totalCatWeight, isCompInfo)
					l := []string{catNameWithWeight, featNameWithWeight, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else if res.Profiles != nil {
			for _, proResult := range res.Profiles.ProfResult {
				var prs proTable

				prs.profilesHeader = []string{"PROFILE", "FEATURE", "STATUS", "DESC"}
				prs.messages = fmt.Sprintf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s", proResult.InterlynkScore, proResult.Grade, res.Meta.NumComponents, EngineVersion, res.Meta.Filename)

				for _, pFeatResult := range proResult.Items {
					var status string
					if pFeatResult.Required {
						if pFeatResult.Ignore {
							// Tool/format limitation â cannot evaluate, not an SBOM deficiency.
							status = "N/A (not evaluated)"
						} else {
							status = fmt.Sprintf("%.1f/10.0", pFeatResult.Score)
						}
					} else if pFeatResult.Additional {
						// Additional fields: conditional mandatory per BSI §5.3 — MUST be present if data exists
						status = fmt.Sprintf("%.1f/10.0 (additional)", pFeatResult.Score)
					} else {
						status = fmt.Sprintf("%.1f/10.0 (optional)", pFeatResult.Score)
					}
					l := []string{proResult.Name, pFeatResult.Key, status, pFeatResult.Desc}
					prs.profilesDoc = append(prs.profilesDoc, l)
				}
				prs.result = proResult
				pros = append(pros, prs)
			}
		}

		if len(profOutDoc) > 0 {
			newTable(profOutDoc, profHeader, "Industry Profile Overviews:")
		}

		// Show category summary table before detailed table
		if res.Comprehensive != nil {
			totalCatWeight := calculateTotalCategoryWeight(res.Comprehensive.CatResult)
			catSummaryRows, catSummaryHeader := buildCategorySummary(res.Comprehensive.CatResult, totalCatWeight)
			newTable(catSummaryRows, catSummaryHeader, "Category Breakdown:")
		}

		if len(outDoc) > 0 {
			newTable(outDoc, header, "Score Breakdown:")
		}

		if len(pros) > 0 {
			for _, prs := range pros {
				fmt.Println(prs.messages)
				fmt.Println()
				newTable(prs.profilesDoc, prs.profilesHeader, "")

				// Summary: three-tier counting for all profiles
				requiredCount, requiredCompliant, requiredNotEvaluated := 0, 0, 0
				additionalCount, additionalCompliant := 0, 0
				optionalCount, optionalPresent := 0, 0

				for _, item := range prs.result.Items {
					if item.Required {
						if item.Ignore {
							// Tool/format limitation â counted separately, not as failure.
							requiredNotEvaluated++
						} else {
							requiredCount++
							if item.Score >= 10.0 {
								requiredCompliant++
							}
						}
					} else if item.Additional {
						additionalCount++
						if item.Score >= 10.0 {
							additionalCompliant++
						}
					} else {
						optionalCount++
						if item.Score >= 10.0 {
							optionalPresent++
						}
					}
				}

				if requiredCount > 0 || requiredNotEvaluated > 0 || additionalCount > 0 || optionalCount > 0 {
					fmt.Println()
					fmt.Println("Summary:")
					if requiredCount > 0 || requiredNotEvaluated > 0 {
						if requiredNotEvaluated > 0 {
							fmt.Printf("Required Fields   : %d/%d compliant (%d not evaluated â tool limitation)\n", requiredCompliant, requiredCount, requiredNotEvaluated)
						} else {
							fmt.Printf("Required Fields   : %d/%d compliant\n", requiredCompliant, requiredCount)
						}
					}
					if additionalCount > 0 {
						fmt.Printf("Additional Fields : %d/%d compliant\n", additionalCompliant, additionalCount)
					}
					if optionalCount > 0 {
						fmt.Printf("Optional Fields   : %d/%d present\n", optionalPresent, optionalCount)
					}
				}
			}
		}

		fmt.Println()
	}
	if hasNonFeatureResults {
		fmt.Println("Love to hear your feedback", form)
	}
}

func formatScore(feat api.FeatureResult) string {
	// if (feat.Key == "comp_eol_eos") || (feat.Key == "comp_malicious") || (feat.Key == "comp_vuln_sev_critical") || (feat.Key == "comp_kev") || (feat.Key == "comp_purl_valid") || (feat.Key == "comp_cpe_valid") || (feat.Key == "comp_epss_high") {
	// 	return "Coming Soon.."
	// }
	return fmt.Sprintf("%.1f/10.0", feat.Score)
}

// calculateTotalCategoryWeight calculates the sum of all category weights excluding compinfo
// since compinfo does not contribute to the overall SBOM Quality Score
func calculateTotalCategoryWeight(catResults []api.CategoryResult) float64 {
	var total float64
	for _, cat := range catResults {
		if cat.Key == "compinfo" {
			continue
		}
		total += cat.Weight
	}
	return total
}

// formatCategoryWithWeight formats category name with its weight percentage
func formatCategoryWithWeight(catName string, catWeight, totalCatWeight float64, isCompInfo bool) string {
	if isCompInfo || totalCatWeight == 0 {
		return catName
	}
	effectiveWeight := (catWeight / totalCatWeight) * 100
	return fmt.Sprintf("%s (%.1f%%)", catName, effectiveWeight)
}

// formatFeatureWithWeight formats feature key with its effective weight percentage.
// orGroup is non-empty when the feature belongs to an OR group (either one satisfies
// the requirement); in that case the full category weight is shown with an OR label.
func formatFeatureWithWeight(featKey, orGroup string, catWeight, featWeight, totalCatWeight float64, isCompInfo bool) string {
	if isCompInfo || totalCatWeight == 0 {
		return featKey
	}

	// For OR features, show the full category weight since either one satisfies the requirement.
	if orGroup != "" {
		effectiveWeight := (catWeight / totalCatWeight) * 100
		return fmt.Sprintf("%s (%.1f%% OR)", featKey, effectiveWeight)
	}

	effectiveWeight := (catWeight * featWeight / totalCatWeight) * 100
	return fmt.Sprintf("%s (%.1f%%)", featKey, effectiveWeight)
}

// buildCategorySummary builds the category summary table data
func buildCategorySummary(catResults []api.CategoryResult, totalCatWeight float64) ([][]string, []string) {
	header := []string{"CATEGORY", "WEIGHT", "SCORE", "GRADE"}
	var rows [][]string

	for _, cat := range catResults {
		var weight string
		if totalCatWeight > 0 {
			weight = fmt.Sprintf("%.1f%%", (cat.Weight/totalCatWeight)*100)
		} else {
			weight = "N/A"
		}
		score := fmt.Sprintf("%.1f/10.0", cat.Score)
		rows = append(rows, []string{cat.Name, weight, score, cat.Grade})
	}

	return rows, header
}

func newTable(doc [][]string, header []string, msg string) {
	if len(doc) > 0 {
		fmt.Println(msg)
		dt := tablewriter.NewWriter(os.Stdout)
		dt.SetHeader(header)
		dt.SetRowLine(true)
		dt.SetAutoMergeCellsByColumnIndex([]int{0})
		dt.AppendBulk(doc)
		dt.Render()
		fmt.Println()
	}
}

// renderFeatureScoreDetailed outputs feature-level scoring results for detailed view
func (r *Reporter) renderFeatureScoreDetailed(result api.Result) {
	if result.Comprehensive == nil || len(result.Comprehensive.CatResult) == 0 {
		return
	}
	catResult := result.Comprehensive.CatResult[0]
	numComponents := result.Meta.NumComponents
	fileName := result.Meta.Filename

	// Header with Profile Context
	fmt.Printf("Feature Quality Score: %.1f/10.0     Grade: %s    Components: %d      EngineVersion: %s    File: %s\n",
		result.Comprehensive.InterlynkScore,
		result.Comprehensive.Grade,
		numComponents,
		EngineVersion,
		fileName)

	// Show profile context
	if result.ProfileContext != "" && result.ProfileContext != "interlynk" {
		fmt.Printf("Profile Context: %s\n\n", getProfileDisplayName(result.ProfileContext))
	} else {
		fmt.Println()
	}

	// Feature Breakdown table using tablewriter
	fmt.Println("Feature Breakdown:")
	dt := tablewriter.NewWriter(os.Stdout)
	dt.SetHeader([]string{"FEATURE", "SCORE", "GRADE", "DESC"})
	dt.SetRowLine(true)

	for _, feat := range catResult.Features {
		grade := scoreToGrade(feat.Score)
		dt.Append([]string{feat.Key, fmt.Sprintf("%.1f/10.0", feat.Score), grade, feat.Desc})
	}
	dt.Render()

	// Overall summary for profile context
	if result.ProfileContext != "" && result.ProfileContext != "interlynk" {
		passed := 0
		for _, feat := range catResult.Features {
			if feat.Score >= 5.0 { // PASS threshold
				passed++
			}
		}
		total := len(catResult.Features)
		fmt.Printf("\nOverall: %d/%d %s requirements passed\n", passed, total, getProfileDisplayName(result.ProfileContext))
	}
}
