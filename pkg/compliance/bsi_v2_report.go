// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"encoding/json"
	"fmt"
	"os"

	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
)

var bsiV2SectionDetails = map[int]bsiSection{
	SBOM_SPEC:         {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification"},
	SBOM_SPEC_VERSION: {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification version"},
	SBOM_BUILD:        {Title: "Level of Detail", ID: "5.1", Required: true, DataField: "build process"},
	SBOM_DEPTH:        {Title: "Level of Detail", ID: "5.1", Required: true, DataField: "depth"},
	SBOM_CREATOR:      {Title: "Required fields sboms ", ID: "5.2.1", Required: true, DataField: "creator of sbom"},
	SBOM_TIMESTAMP:    {Title: "Required fields sboms", ID: "5.2.1", Required: true, DataField: "timestamp"},
	SBOM_URI:          {Title: "Additional fields sboms", ID: "5.3.1", Required: false, DataField: "SBOM-URI"},
}

func bsiV2JSONReport(dtb *db.DB, fileName string) {
	name := "BSI TR-03183-2 v2.0.0 Compliance Report"
	revision := "TR-03183-2 (2.0.0)"
	jr := newJSONReport(name, revision)
	jr.Run.FileName = fileName

	score := bsiAggregateScore(dtb)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = constructSections(dtb)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func bsiV2DetailedReport(dtb *db.DB, fileName string) {
	table := tablewriter.NewWriter(os.Stdout)
	score := bsiAggregateScore(dtb)

	fmt.Printf("BSI TR-03183-2 v2.0.0 Compliance Report \n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := constructSections(dtb)

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID = sectionID + "*"
		}
		table.Append([]string{section.ElementID, sectionID, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
	}
	table.Render()
}

func bsiV2BasicReport(dtb *db.DB, fileName string) {
	score := bsiAggregateScore(dtb)
	fmt.Printf("BSI TR-03183-2 v2.0.0 Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
