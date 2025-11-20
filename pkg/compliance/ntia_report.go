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

package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var ntiaSectionDetails = map[int]ntiaSection{
	SBOM_MACHINE_FORMAT: {Title: "Automation Support", ID: "1.1", Required: true, DataField: "Machine-Readable Formats"},
	SBOM_CREATOR:        {Title: "Required fields sboms ", ID: "2.1", Required: true, DataField: "Author"},
	SBOM_TIMESTAMP:      {Title: "Required fields sboms", ID: "2.2", Required: true, DataField: "Timestamp"},
	SBOM_DEPENDENCY:     {Title: "Required fields sboms", ID: "2.3", Required: true, DataField: "Dependencies"},
	COMP_NAME:           {Title: "Required fields components", ID: "2.4", Required: true, DataField: "Package Name"},
	COMP_DEPTH:          {Title: "Required fields components", ID: "2.5", Required: true, DataField: "Dependencies on other components"},
	COMP_CREATOR:        {Title: "Required fields component", ID: "2.6", Required: true, DataField: "Package Supplier"},
	PACK_SUPPLIER:       {Title: "Required fields component", ID: "2.6", Required: true, DataField: "Package Supplier"},
	COMP_VERSION:        {Title: "Required fields components", ID: "2.7", Required: true, DataField: "Package Version"},
	COMP_OTHER_UNIQ_IDS: {Title: "Required fields component", ID: "2.8", Required: true, DataField: "Other Uniq IDs"},
}

type ntiaSection struct {
	Title         string  `json:"section_title"`
	ID            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementID     string  `json:"element_id"`
	ElementResult string  `json:"element_result"`
	Score         float64 `json:"score"`
}

type ntiaComplianceReport struct {
	Name     string        `json:"report_name"`
	Subtitle string        `json:"subtitle"`
	Revision string        `json:"revision"`
	Run      run           `json:"run"`
	Tool     tool          `json:"tool"`
	Summary  Summary       `json:"summary"`
	Sections []ntiaSection `json:"sections"`
}

func newNtiaJSONReport() *ntiaComplianceReport {
	return &ntiaComplianceReport{
		Name:     "NTIA-minimum elements Compliance Report",
		Subtitle: "Part 2: Software Bill of Materials (SBOM)",
		Revision: "",
		Run: run{
			ID:            uuid.New().String(),
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			FileName:      "",
			EngineVersion: "1",
		},
		Tool: tool{
			Name:    "sbomqs",
			Version: version.GetVersionInfo().GitVersion,
			Vendor:  "Interlynk (support@interlynk.io)",
		},
	}
}

func ntiaJSONReport(db *db.DB, fileName string) {
	jr := newNtiaJSONReport()
	jr.Run.FileName = fileName

	score := ntiaAggregateScore(db)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = ntiaConstructSections(db)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func ntiaConstructSections(db *db.DB) []ntiaSection {
	var sections []ntiaSection
	allIDs := db.GetAllIDs()
	for _, id := range allIDs {
		records := db.GetRecordsByID(id)

		for _, r := range records {
			section := ntiaSectionDetails[r.CheckKey]
			newSection := ntiaSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := ntiaKeyIDScore(db, r.CheckKey, r.ID)
			newSection.Score = score.totalScore()
			if r.ID == "doc" {
				newSection.ElementID = "sbom"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}
	// Group sections by ElementID
	sectionsByElementID := make(map[string][]ntiaSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	// Sort each group of sections by section.ID and ensure "SBOM Data Fields" comes first within its group if it exists
	var sortedSections []ntiaSection
	var sbomLevelSections []ntiaSection
	for elementID, group := range sectionsByElementID {
		sort.Slice(group, func(i, j int) bool {
			return group[i].ID < group[j].ID
		})
		if elementID == "SBOM Level" {
			sbomLevelSections = group
		} else {
			sortedSections = append(sortedSections, group...)
		}
	}

	// Place "SBOM Level" sections at the top
	sortedSections = append(sbomLevelSections, sortedSections...)

	return sortedSections
}

func ntiaDetailedReport(db *db.DB, fileName string, colorOutput bool) {
	table := tablewriter.NewWriter(os.Stdout)
	score := ntiaAggregateScore(db)

	fmt.Printf("NTIA Report\n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ELEMENT ID", "Section ID", "NTIA minimum elements", "Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := ntiaConstructSections(db)

	// Sort sections by ElementId and then by SectionId
	sort.Slice(sections, func(i, j int) bool {
		if sections[i].ElementID == sections[j].ElementID {
			return sections[i].ID < sections[j].ID
		}
		return sections[i].ElementID < sections[j].ElementID
	})

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID = sectionID + "*"
		}

		if colorOutput {
			// disable tablewriter's auto-wrapping
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
			table.Append([]string{section.ElementID, sectionID, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
		}
	}
	table.Render()
}

func ntiaBasicReport(db *db.DB, fileName string) {
	score := ntiaAggregateScore(db)
	fmt.Printf("NTIA Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
