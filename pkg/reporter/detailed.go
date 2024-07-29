// Copyright 2023 Interlynk.io
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
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
)

func (r *Reporter) detailedReport() {
	for index, path := range r.Paths {
		doc := r.Docs[index]
		scores := r.Scores[index]

		outDoc := [][]string{}

		for _, score := range scores.ScoreList() {
			var l []string
			if score.Ignore() {
				l = []string{score.Category(), score.Feature(), " - ", score.Descr()}
			} else {
				l = []string{score.Category(), score.Feature(), fmt.Sprintf("%0.1f/10.0", score.Score()), score.Descr()}
			}
			outDoc = append(outDoc, l)
		}

		sort.Slice(outDoc, func(i, j int) bool {
			switch strings.Compare(outDoc[i][0], outDoc[j][0]) {
			case -1:
				return true
			case 1:
				return false
			}
			return outDoc[i][1] < outDoc[j][1]
		})

		fmt.Printf("SBOM Quality by Interlynk Score:%0.1f\tcomponents:%d\t%s\n", scores.AvgScore(), len(doc.Components()), path)
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Category", "Feature", "Score", "Desc"})
		table.SetRowLine(true)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.AppendBulk(outDoc)
		table.Render()
	}
}

func (r *ScvsReporter) detailedScvsReport() {
	for index := range r.Paths {
		// doc := r.Docs[index]
		scores := r.Scores[index]

		outDoc := [][]string{}

		for _, score := range scores.ScoreList() {
			var l []string

			l = []string{score.Feature(), score.Score()}

			outDoc = append(outDoc, l)
		}

		sort.Slice(outDoc, func(i, j int) bool {
			switch strings.Compare(outDoc[i][0], outDoc[j][0]) {
			case -1:
				return true
			case 1:
				return false
			}
			return outDoc[i][1] < outDoc[j][1]
		})

		// fmt.Printf("SBOM Quality by Interlynk Score:%0.1f\tcomponents:%d\t%s\n", scores.AvgScore(), len(doc.Components()), path)
		fmt.Println("Analysis of SCVS Report by OWASP Organization using SBOMQS Tool")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Feature", "Level 3"})
		table.SetRowLine(true)
		table.SetAutoWrapText(false)
		table.SetColMinWidth(0, 60)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.AppendBulk(outDoc)
		table.Render()
	}
}
