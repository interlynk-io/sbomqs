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

var cisa2026SectionDetails = map[int]bsiSection{
	// SBOM Metadata
	CISA2026_SBOM_DATA_FORMAT:        {Title: "SBOM Metadata", ID: "1.1", Required: true, DataField: "Data Format"},
	CISA2026_SBOM_SPEC_VERSION:       {Title: "SBOM Metadata", ID: "1.2", Required: true, DataField: "Spec Version"},
	CISA2026_SBOM_AUTHOR:             {Title: "SBOM Metadata", ID: "1.3", Required: true, DataField: "Author"},
	CISA2026_SBOM_TOOL_NAME:          {Title: "SBOM Metadata", ID: "1.4", Required: true, DataField: "Tool Name"},
	CISA2026_SBOM_TOOL_VERSION:       {Title: "SBOM Metadata", ID: "1.5", Required: true, DataField: "Tool Version"},
	CISA2026_SBOM_VERSION:            {Title: "SBOM Metadata", ID: "1.6", Required: true, DataField: "SBOM Version"},
	CISA2026_SBOM_TIMESTAMP:          {Title: "SBOM Metadata", ID: "1.7", Required: true, DataField: "Timestamp"},
	CISA2026_SBOM_GENERATION_CONTEXT: {Title: "SBOM Metadata", ID: "1.8", Required: true, DataField: "Generation Context"},
	CISA2026_SBOM_RELATIONSHIPS:      {Title: "SBOM Metadata", ID: "1.9", Required: true, DataField: "Relationships"},
	CISA2026_SBOM_SIGNATURE:          {Title: "SBOM Metadata", ID: "1.10", Required: false, DataField: "Signature"},

	// Component Data
	CISA2026_COMP_NAME:       {Title: "Component Data", ID: "2.1", Required: true, DataField: "Name"},
	CISA2026_COMP_VERSION:    {Title: "Component Data", ID: "2.2", Required: true, DataField: "Version"},
	CISA2026_COMP_UNIQ_ID:    {Title: "Component Data", ID: "2.3", Required: true, DataField: "Unique ID"},
	CISA2026_COMP_PRODUCER:   {Title: "Component Data", ID: "2.4", Required: true, DataField: "Producer"},
	CISA2026_COMP_HASH_VALUE: {Title: "Component Data", ID: "2.5", Required: true, DataField: "Hash Value"},
	CISA2026_COMP_HASH_ALGO:  {Title: "Component Data", ID: "2.6", Required: true, DataField: "Hash Algorithm"},
	CISA2026_COMP_LICENSE:    {Title: "Component Data", ID: "2.7", Required: true, DataField: "License"},
}

func cisa2026JSONReport(dtb *db.DB, fileName string) {
	name := "NTIA Minimum Elements (2026) Compliance Report"
	revision := "CISA 2026 Minimum Elements"
	jr := newJSONReport(name, revision)
	jr.Run.FileName = fileName

	score := cisa2026AggregateScore(dtb)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = constructCISA2026Sections(dtb)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func constructCISA2026Sections(dtb *db.DB) []bsiSection {
	allIDs := dtb.GetAllIDs()

	estimatedCapacity := len(allIDs) * 5
	sections := make([]bsiSection, 0, estimatedCapacity)

	for _, id := range allIDs {
		records := dtb.GetRecordsByID(id)

		for _, r := range records {
			section, ok := cisa2026SectionDetails[r.CheckKey]
			if !ok {
				continue
			}
			newSection := bsiSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := cisa2026KeyIDScore(dtb, r.CheckKey, r.ID)
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

func cisa2026DetailedReport(dtb *db.DB, fileName string, colorOutput bool) {
	table := tablewriter.NewWriter(os.Stdout)
	score := cisa2026AggregateScore(dtb)

	fmt.Printf("NTIA Minimum Elements (2026) Compliance Report \n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := constructCISA2026Sections(dtb)

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

func cisa2026BasicReport(dtb *db.DB, fileName string) {
	score := cisa2026AggregateScore(dtb)
	fmt.Printf("NTIA Minimum Elements (2026) Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
