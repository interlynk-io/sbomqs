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

package reporter

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

func (r *Reporter) detailedReport() {
	for index, path := range r.Paths {
		doc := r.Docs[index]
		scores := r.Scores[index]
		colorOp := r.Color
		outDoc := [][]string{}

		for _, score := range scores.ScoreList() {
			var l []string
			if score.Feature() == "Component With Original Licenses" {
				outDoc = append(outDoc, []string{"", "", "", ""})
			}
			if score.Ignore() {
				l = []string{score.Category(), score.Feature(), " - ", score.Descr()}
			} else {
				l = []string{score.Category(), score.Feature(), fmt.Sprintf("%0.1f/10.0", score.Score()), score.Descr()}
			}
			outDoc = append(outDoc, l)
		}

		fmt.Printf("SBOM Quality by Interlynk Score:%0.1f\tcomponents:%d\t%s\n", scores.AvgScore(), len(doc.Components()), path)

		// Initialize tablewriter table with borders
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Category", "Feature", "Score", "Desc"})
		table.SetRowLine(true)
		table.SetAutoMergeCellsByColumnIndex([]int{0})

		if colorOp {
			for _, row := range outDoc {
				scoreText := row[2]
				scoreValue := parseScore(row[2])

				// Apply color based on the score value
				var coloredScore string
				switch {
				case scoreValue < 5.0:
					coloredScore = color.New(color.FgRed).Sprintf("%s", scoreText)
				default:
					coloredScore = color.New(color.FgGreen).Sprintf("%s", scoreText)
				}
				coloredCategory := color.New(color.FgHiMagenta).Sprint(row[0])
				coloredFeature := color.New(color.FgHiCyan).Sprint(row[1])
				coloredDesc := color.New(color.FgHiBlue).Sprint(row[3])

				table.Append([]string{coloredCategory, coloredFeature, coloredScore, coloredDesc})
			}
		} else {
			table.AppendBulk(outDoc)
		}

		table.Render()
	}
}

// parseScore extracts the numeric score value from a formatted score string (e.g., "9.7/10.0").
func parseScore(scoreStr string) float64 {
	var scoreValue float64
	if _, err := fmt.Sscanf(scoreStr, "%f", &scoreValue); err != nil {
		fmt.Printf("Error scanning score: %v\n", err)
	}

	return scoreValue
}
