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

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/olekukonko/tablewriter"
)

func (r *Reporter) detailedReport() {
	form := "https://forms.gle/anFSspwrk7uSfD7Q6"

	for _, r := range r.Results {
		// buffers for table rows
		outDoc := [][]string{}     // detailed comprehensive rows
		profOutDoc := [][]string{} // profile summary rows

		header := []string{}
		profHeader := []string{}

		if r.Comprehensive != nil && r.Profiles != nil {
			var score float64
			var grade string

			for _, r := range r.Profiles.ProfResult {
				score = r.Score
				grade = r.Grade
			}

			fmt.Printf("\n  SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t SBOMQS Engine: %s\n\n  File: %s\n", score, grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			profHeader = []string{"PROFILE", "SCORE", "GRADE"}

			for _, proResult := range r.Profiles.ProfResult {
				l := []string{proResult.Name, fmt.Sprintf("%.1f/10.0", proResult.Score), proResult.Grade}
				profOutDoc = append(profOutDoc, l)
			}

			header = []string{"Category", "Feature", "Score", "Desc"}
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					l := []string{cat.Name, feat.Key, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}

		} else if r.Comprehensive != nil {

			fmt.Printf("\n  SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t SBOMQS Engine: %s\n\n  File: %s\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			header = []string{"Category", "Feature", "Score", "Desc"}
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					l := []string{cat.Name, feat.Key, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else if r.Profiles != nil {

			var score float64
			var grade string

			for _, r := range r.Profiles.ProfResult {
				score = r.Score
				grade = r.Grade
			}

			fmt.Printf("\n  SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t SBOMQS Engine: %s\n\n  File: %s\n", score, grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			header = []string{"Requirment", "Feature", "Status", "Desc"}

			for _, proResult := range r.Profiles.ProfResult {
				for _, pFeatResult := range proResult.Items {
					l := []string{proResult.Name, pFeatResult.Key, fmt.Sprintf("%.1f/10.0", pFeatResult.Score), pFeatResult.Desc}
					outDoc = append(outDoc, l)
				}
			}
		}

		// Render profile summary table (only if we have rows)
		if len(profOutDoc) > 0 {
			fmt.Println()
			fmt.Println("Profile Summary Scores:")
			pt := tablewriter.NewWriter(os.Stdout)
			pt.SetHeader(profHeader)
			pt.SetRowLine(true)
			pt.SetAutoMergeCellsByColumnIndex([]int{0})
			pt.AppendBulk(profOutDoc)
			pt.Render()
			fmt.Println()
			fmt.Println()
		}

		// Render detailed comprehensive table (only if we have rows)
		if len(outDoc) > 0 {
			fmt.Println("Interlynk Detailed Score:")
			dt := tablewriter.NewWriter(os.Stdout)
			dt.SetHeader(header)
			dt.SetRowLine(true)
			dt.SetAutoMergeCellsByColumnIndex([]int{0})
			dt.AppendBulk(outDoc)
			dt.Render()
			fmt.Println()
		}
		fmt.Println()
		fmt.Println()
	}
	fmt.Println("\nFeedback form on enhancing the SBOM quality: ", form)
}

func formatScore(feat api.FeatureResult) string {
	if (feat.Key == "comp_eol_eos") || (feat.Key == "comp_malicious") || (feat.Key == "comp_vuln_sev_critical") || (feat.Key == "comp_epss_high") {
		return "N/A"
	}
	return fmt.Sprintf("%.1f/10.0", feat.Score)
}
