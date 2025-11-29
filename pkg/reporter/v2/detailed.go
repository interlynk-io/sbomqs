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
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/olekukonko/tablewriter"
)

type proTable struct {
	profilesDoc    [][]string
	profilesHeader []string
	messages       string
}

func (r *Reporter) detailedReport() {
	form := "https://forms.gle/anFSspwrk7uSfD7Q6"

	for _, r := range r.Results {
		// buffers for table rows
		outDoc := [][]string{}     // detailed comprehensive rows
		profOutDoc := [][]string{} // profile summary rows

		var pros []proTable

		header := []string{}
		profHeader := []string{}

		if r.Comprehensive != nil && r.Profiles != nil {
			fmt.Printf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s\n\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			profHeader = []string{"PROFILE", "SCORE", "GRADE"}

			for _, proResult := range r.Profiles.ProfResult {
				l := []string{proResult.Name, fmt.Sprintf("%.1f/10.0", proResult.Score), proResult.Grade}
				profOutDoc = append(profOutDoc, l)
			}

			totalCatWeight := calculateTotalCategoryWeight(r.Comprehensive.CatResult)
			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range r.Comprehensive.CatResult {
				isCompInfo := cat.Key == "compinfo"
				catNameWithWeight := formatCategoryWithWeight(cat.Name, cat.Weight, totalCatWeight, isCompInfo)
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					featNameWithWeight := formatFeatureWithWeight(feat.Key, cat.Weight, feat.Weight, totalCatWeight, isCompInfo)
					l := []string{catNameWithWeight, featNameWithWeight, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}

				if cat.Key == "compinfo" {
					l := []string{catNameWithWeight, "NOTE: Register Interest for Component Analysis", "", "https://forms.gle/WVoB3DrX9NKnzfhV8"}
					outDoc = append(outDoc, l)
				}
			}

		} else if r.Comprehensive != nil {

			fmt.Printf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			totalCatWeight := calculateTotalCategoryWeight(r.Comprehensive.CatResult)
			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range r.Comprehensive.CatResult {
				isCompInfo := cat.Key == "compinfo"
				catNameWithWeight := formatCategoryWithWeight(cat.Name, cat.Weight, totalCatWeight, isCompInfo)
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					featNameWithWeight := formatFeatureWithWeight(feat.Key, cat.Weight, feat.Weight, totalCatWeight, isCompInfo)
					l := []string{catNameWithWeight, featNameWithWeight, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else if r.Profiles != nil {
			for _, proResult := range r.Profiles.ProfResult {
				var prs proTable

				prs.profilesHeader = []string{"PROFILE", "FEATURE", "STATUS", "DESC"}
				prs.messages = fmt.Sprintf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s", proResult.InterlynkScore, proResult.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

				for _, pFeatResult := range proResult.Items {
					var status string
					if pFeatResult.Required {
						status = fmt.Sprintf("%.1f/10.0", pFeatResult.Score)
					} else {
						// Optional fields show score format but marked as optional
						status = fmt.Sprintf("%.1f/10.0 (optional)", pFeatResult.Score)
					}
					l := []string{proResult.Name, pFeatResult.Key, status, pFeatResult.Desc}
					prs.profilesDoc = append(prs.profilesDoc, l)
				}
				pros = append(pros, prs)
			}
		}

		if len(profOutDoc) > 0 {
			newTable(profOutDoc, profHeader, "Industry Profile Overviews:")
		}

		// Show category summary table before detailed table
		if r.Comprehensive != nil {
			totalCatWeight := calculateTotalCategoryWeight(r.Comprehensive.CatResult)
			catSummaryRows, catSummaryHeader := buildCategorySummary(r.Comprehensive.CatResult, totalCatWeight)
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
				
				// Add summary for NTIA and OCT profiles showing required vs optional fields
				if r.Profiles != nil && len(r.Profiles.ProfResult) > 0 {
					for _, proResult := range r.Profiles.ProfResult {
						if proResult.Name == "NTIA Minimum Elements (2021)" || proResult.Name == "NTIA Minimum Elements (2025) - RFC" || proResult.Name == "OpenChain Telco v1.1" {
							requiredCount, requiredCompliant := 0, 0
							optionalCount, optionalPresent := 0, 0
							
							for _, item := range proResult.Items {
								if item.Required {
									requiredCount++
									if item.Score >= 10.0 {
										requiredCompliant++
									}
								} else {
									optionalCount++
									if item.Score >= 10.0 {
										optionalPresent++
									}
								}
							}
							
							if requiredCount > 0 || optionalCount > 0 {
								fmt.Println()
								fmt.Println("Summary:")
								fmt.Printf("Required Fields : %d/%d compliant\n", requiredCompliant, requiredCount)
								if optionalCount > 0 {
									fmt.Printf("Optional Fields : %d/%d present\n", optionalPresent, optionalCount)
								}
							}
							break
						}
					}
				}
			}
		}

		fmt.Println()
	}
	fmt.Println("Love to hear your feedback", form)
}

func formatScore(feat api.FeatureResult) string {
	if (feat.Key == "comp_eol_eos") || (feat.Key == "comp_malicious") || (feat.Key == "comp_vuln_sev_critical") || (feat.Key == "comp_kev") || (feat.Key == "comp_purl_valid") || (feat.Key == "comp_cpe_valid") || (feat.Key == "comp_epss_high") {
		return "Coming Soon.."
	}
	return fmt.Sprintf("%.1f/10.0", feat.Score)
}

// calculateTotalCategoryWeight calculates the sum of all category weights excluding compinfo
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

// orFeatures defines features that are OR conditions (either one satisfies the requirement)
var orFeatures = map[string]bool{
	"comp_with_purl": true,
	"comp_with_cpe":  true,
}

// formatCategoryWithWeight formats category name with its weight percentage
func formatCategoryWithWeight(catName string, catWeight, totalCatWeight float64, isCompInfo bool) string {
	if isCompInfo {
		return catName
	}
	effectiveWeight := (catWeight / totalCatWeight) * 100
	return fmt.Sprintf("%s (%.1f%%)", catName, effectiveWeight)
}

// formatFeatureWithWeight formats feature key with its effective weight percentage
func formatFeatureWithWeight(featKey string, catWeight, featWeight, totalCatWeight float64, isCompInfo bool) string {
	if isCompInfo {
		return featKey
	}

	// For OR features, show the full category weight since either one satisfies the requirement
	if orFeatures[featKey] {
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
		if cat.Key == "compinfo" {
			continue // Skip component quality (informational only)
		}
		weight := fmt.Sprintf("%.1f%%", (cat.Weight/totalCatWeight)*100)
		score := fmt.Sprintf("%.1f/10.0", cat.Score)
		grade := formulae.ToGrade(cat.Score)
		rows = append(rows, []string{cat.Name, weight, score, grade})
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
