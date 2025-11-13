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
		outDoc := [][]string{}
		header := []string{}
		if r.Comprehensive != nil && r.Profiles != nil {
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					l := []string{cat.Name, feat.Key, fmt.Sprintf("%.1f/10.0", feat.Score), feat.Desc}
					outDoc = append(outDoc, l)
				}
			}

			for _, pro := range r.Profiles.ProfResult {
				for _, pf := range pro.Items {
					l := []string{pro.Name, pf.Key, fmt.Sprintf("%.1f/10.0", pf.Score), pf.Desc}
					outDoc = append(outDoc, l)
				}
			}

		} else if r.Comprehensive != nil {
			header = []string{"Category", "Feature", "Score", "Desc"}
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					l := []string{cat.Name, feat.Key, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else if r.Profiles != nil {
			header = []string{"Requirment", "Feature", "Status", "Desc"}

			for _, proResult := range r.Profiles.ProfResult {
				for _, pFeatResult := range proResult.Items {
					l := []string{proResult.Name, pFeatResult.Key, fmt.Sprintf("%.1f/10.0", pFeatResult.Score), pFeatResult.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else {
			// no scoring
		}

		fmt.Printf("\n  SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t SBOMQS Engine: %s\n\n  File: %s\n", r.InterlynkScore, r.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

		// Initialize tablewriter table with borders
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		table.SetRowLine(true)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.AppendBulk(outDoc)
		table.Render()
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
