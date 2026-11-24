// Copyright 2026 Interlynk.io
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

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
)

var enisaSectionDetails = map[int]bsiSection{
	// SBOM Metadata
	ENISA_SBOM_AUTHOR:             {Title: "SBOM Metadata", ID: "1.1", Required: true, DataField: "Author"},
	ENISA_SBOM_TIMESTAMP:           {Title: "SBOM Metadata", ID: "1.2", Required: true, DataField: "Timestamp"},
	ENISA_SBOM_TOOL_NAME:           {Title: "SBOM Metadata", ID: "1.3", Required: true, DataField: "Tool Name"},
	ENISA_SBOM_GENERATION_CONTEXT:  {Title: "SBOM Metadata", ID: "1.4", Required: true, DataField: "Generation Context"},

	// Component Data
	ENISA_COMP_NAME:        {Title: "Component Data", ID: "2.1", Required: true, DataField: "Name"},
	ENISA_COMP_VERSION:     {Title: "Component Data", ID: "2.2", Required: true, DataField: "Version"},
	ENISA_COMP_UNIQ_ID:     {Title: "Component Data", ID: "2.3", Required: true, DataField: "Unique ID"},
	ENISA_COMP_PRODUCER:    {Title: "Component Data", ID: "2.4", Required: true, DataField: "Producer"},
	ENISA_COMP_HASH_VALUE:  {Title: "Component Data", ID: "2.5", Required: true, DataField: "Hash Value"},
	ENISA_COMP_HASH_ALGO:   {Title: "Component Data", ID: "2.6", Required: true, DataField: "Hash Algorithm"},
	ENISA_COMP_LICENSE:     {Title: "Component Data", ID: "2.7", Required: true, DataField: "License"},
	ENISA_COMP_RELATIONSHIPS: {Title: "Component Data", ID: "2.8", Required: true, DataField: "Relationships"},
}

func enisaJSONReport(dtb *db.DB, fileName string) {
	name := "ENISA SBOM Minimum Elements Compliance Report"
	revision := "ENISA SBOM Minimum Elements v1.20"
	jr := newJSONReport(name, revision)
	jr.Run.FileName = fileName

	score := enisaAggregateScore(dtb)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = constructENISASections(dtb)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func constructENISASections(dtb *db.DB) []bsiSection {
	allIDs := dtb.GetAllIDs()

	estimatedCapacity := len(allIDs) * 5
	sections := make([]bsiSection, 0, estimatedCapacity)

	for _, id := range allIDs {
		records := dtb.GetRecordsByID(id)

		for _, r := range records {
			section, ok := enisaSectionDetails[r.CheckKey]
			if !ok {
				continue
			}
			newSection := bsiSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := enisaKeyIDScore(dtb, r.CheckKey, r.ID)
			if section.Required {
				newSection.Score = score.totalScore()
			} else {
				newSection.Score = score.totalOptionalScore()
			}
			if r.ID == "doc" {
				newSection.ElementID = "SBOM"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}

	sectionsByElementID := make(map[string][]bsiSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	sortedSections := make([]bsiSection, 0, len(sections))
	var sbomLevelSections []bsiSection
	for elementID, group := range sectionsByElementID {
		if elementID == "SBOM" {
			sbomLevelSections = group
		} else {
			sortedSections = append(sortedSections, group...)
		}
	}

	sortedSections = append(sbomLevelSections, sortedSections...)

	return sortedSections
}

func enisaDetailedReport(dtb *db.DB, fileName string, colorOutput bool) {
	table := tablewriter.NewWriter(os.Stdout)
	score := enisaAggregateScore(dtb)

	fmt.Printf("ENISA SBOM Minimum Elements Compliance Report \n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := constructENISASections(dtb)

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID += "*"
		}

		if colorOutput {
			table.SetAutoWrapText(false)
			columnWidth := 30
			common.SetHeaderColor(table, 5)

			table = common.ColorTable(table,
				section.ElementID,
				section.ID,
				section.ElementResult,
				section.DataField,
				section.Score,
				columnWidth)
		} else {
			table.Append([]string{section.ElementID, sectionID, section.DataField, wrapResult(section.ElementResult), fmt.Sprintf("%0.1f", section.Score)})
		}
	}
	table.Render()
}

func enisaBasicReport(dtb *db.DB, fileName string) {
	score := enisaAggregateScore(dtb)
	fmt.Printf("ENISA SBOM Minimum Elements Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
