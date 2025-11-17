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

			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					l := []string{cat.Name, feat.Key, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}

				if cat.Key == "compinfo" {
					l := []string{cat.Name, "NOTE: Register Interest for Component Analysis", "", "https://forms.gle/WVoB3DrX9NKnzfhV8"}
					outDoc = append(outDoc, l)
				}
			}

		} else if r.Comprehensive != nil {

			fmt.Printf("SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

			header = []string{"CATEGORY", "FEATURE", "SCORE", "DESC"}
			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					scoreStr := formatScore(feat)
					l := []string{cat.Name, feat.Key, scoreStr, feat.Desc}
					outDoc = append(outDoc, l)
				}
			}
		} else if r.Profiles != nil {
			for _, proResult := range r.Profiles.ProfResult {
				var prs proTable

				prs.profilesHeader = []string{"PROFILE", "FEATURE", "STATUS", "DESC"}
				prs.messages = fmt.Sprintf("\n SBOM Quality Score: %0.1f/10.0\t Grade: %s\tComponents: %d \t EngineVersion: %s\tFile: %s", proResult.InterlynkScore, proResult.Grade, r.Meta.NumComponents, EngineVersion, r.Meta.Filename)

				for _, pFeatResult := range proResult.Items {
					l := []string{proResult.Name, pFeatResult.Key, fmt.Sprintf("%.1f/10.0", pFeatResult.Score), pFeatResult.Desc}
					prs.profilesDoc = append(prs.profilesDoc, l)
				}
				pros = append(pros, prs)
			}
		}

		if len(profOutDoc) > 0 {
			newTable(profOutDoc, profHeader, "Profile Summary Scores:")
		}

		if len(outDoc) > 0 {
			newTable(outDoc, header, "Interlynk Detailed Score:")
		}

		if len(pros) > 0 {
			for _, prs := range pros {
				fmt.Print(prs.messages)
				newTable(prs.profilesDoc, prs.profilesHeader, "")
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
