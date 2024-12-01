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

package fsct

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

// nolint
const (
	SBOM_AUTHOR = iota
	SBOM_TIMESTAMP
	SBOM_TYPE
	SBOM_PRIMARY_COMPONENT
	COMP_NAME
	COMP_VERSION
	COMP_SUPPLIER
	COMP_UNIQ_ID
	COMP_CHECKSUM
	COMP_RELATIONSHIP
	COMP_LICENSE
	COMP_COPYRIGHT
)

var fsctSectionDetails = map[int]fsctSection{
	SBOM_AUTHOR:            {Title: "SBOM Level", ID: "2.2.1.1", Required: true, DataField: "SBOM Author"},
	SBOM_TIMESTAMP:         {Title: "SBOM Level", ID: "2.2.1.2", Required: true, DataField: "SBOM Timestamp"},
	SBOM_TYPE:              {Title: "SBOM Level", ID: "2.2.1.3", Required: false, DataField: "SBOM Type"},
	SBOM_PRIMARY_COMPONENT: {Title: "SBOM Level", ID: "2.2.1.4", Required: true, DataField: "Primary Component"},
	COMP_NAME:              {Title: "Component Level", ID: "2.2.2.1", Required: true, DataField: "Component Name"},
	COMP_VERSION:           {Title: "Component Level", ID: "2.2.2.2", Required: true, DataField: "Component Version"},
	COMP_SUPPLIER:          {Title: "Component Level", ID: "2.2.2.3", Required: true, DataField: "Component Supplier"},
	COMP_UNIQ_ID:           {Title: "Component Level", ID: "2.2.2.4", Required: true, DataField: "Component Unique ID"},
	COMP_CHECKSUM:          {Title: "Component Level", ID: "2.2.2.5", Required: true, DataField: "Component Checksum"},
	COMP_RELATIONSHIP:      {Title: "Component Level", ID: "2.2.2.6", Required: true, DataField: "Component Relationship"},
	COMP_LICENSE:           {Title: "Component Level", ID: "2.2.2.7", Required: true, DataField: "Component License"},
	COMP_COPYRIGHT:         {Title: "Component Level", ID: "2.2.2.8", Required: true, DataField: "Component Copyright"},
}

type fsctSection struct {
	Title         string  `json:"section_title"`
	ID            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementID     string  `json:"element_id"`
	ElementResult string  `json:"element_result"`
	Score         float64 `json:"score"`
	Maturity      string  `json:"maturity"`
}
type run struct {
	ID            string `json:"id"`
	GeneratedAt   string `json:"generated_at"`
	FileName      string `json:"file_name"`
	EngineVersion string `json:"compliance_engine_version"`
}
type tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
}
type Summary struct {
	TotalScore float64 `json:"total_score"`
	MaxScore   float64 `json:"max_score"`
	// TotalRequiredScore float64 `json:"required_elements_score"`
	// TotalOptionalScore float64 `json:"optional_elements_score"`
}

type fsctComplianceReport struct {
	Name     string        `json:"report_name"`
	Subtitle string        `json:"subtitle"`
	Revision string        `json:"revision"`
	Run      run           `json:"run"`
	Tool     tool          `json:"tool"`
	Summary  Summary       `json:"summary"`
	Sections []fsctSection `json:"sections"`
}

func newFsctJSONReport() *fsctComplianceReport {
	return &fsctComplianceReport{
		Name:     "Framing Software Component Transparency (v3)",
		Subtitle: "NTIA Minimum Elelments 3rd Edition",
		Revision: "3rd Edition",
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

func fsctJSONReport(db *db.DB, fileName string) {
	jr := newFsctJSONReport()
	jr.Run.FileName = fileName

	score := fsctAggregateScore(db)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	// summary.TotalRequiredScore = score.totalRequiredScore()
	// summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = fsctConstructSections(db)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func fsctConstructSections(db *db.DB) []fsctSection {
	var sections []fsctSection
	allIDs := db.GetAllIDs()
	for _, id := range allIDs {
		records := db.GetRecordsByID(id)
		for _, r := range records {
			section := fsctSectionDetails[r.CheckKey]
			newSection := fsctSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
				Maturity:  r.Maturity,
			}
			score := fsctKeyIDScore(db, r.CheckKey, r.ID)
			newSection.Score = score.totalScore()
			if r.ID == "doc" {
				newSection.ElementID = "SBOM Level"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}

	// Group sections by ElementID
	sectionsByElementID := make(map[string][]fsctSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	// Sort each group of sections by section.ID and ensure "SBOM Level" comes first within its group if it exists
	var sortedSections []fsctSection
	var sbomLevelSections []fsctSection
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

func fsctDetailedReport(db *db.DB, fileName string, coloredOutput bool) {
	table := tablewriter.NewWriter(os.Stdout)
	score := fsctAggregateScore(db)

	fmt.Printf("Framing Software Component Transparency (v3)\n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f for %s\n", score.totalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score", "Maturity"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	if coloredOutput {
		common.SetHeaderColor(table, 6)
	}

	sections := fsctConstructSections(db)

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID += "*"
		}

		if coloredOutput {

			maturityColor := getMaturityColor(section.Maturity)

			table.Rich([]string{
				section.ElementID,
				sectionID,
				section.DataField,
				section.ElementResult,
				fmt.Sprintf("%0.1f", section.Score),
				section.Maturity,
			}, []tablewriter.Colors{
				{tablewriter.FgHiMagentaColor, tablewriter.Bold},
				{tablewriter.FgHiCyanColor},
				{tablewriter.FgHiBlueColor, tablewriter.Bold},
				{tablewriter.FgHiCyanColor, tablewriter.Bold},
				maturityColor,
				maturityColor,
			})
		} else {
			table.Append([]string{
				section.ElementID,
				sectionID,
				section.DataField,
				section.ElementResult,
				fmt.Sprintf("%0.1f", section.Score),
				section.Maturity,
			})
		}
	}
	table.Render()
}

func fsctBasicReport(db *db.DB, fileName string) {
	score := fsctAggregateScore(db)
	fmt.Printf("Framing Software Component Transparency (v3)\n")
	fmt.Printf("Score:%0.1f for %s\n", score.totalScore(), fileName)
}

func getMaturityColor(maturity string) tablewriter.Colors {
	switch maturity {
	case "None":
		return tablewriter.Colors{tablewriter.FgRedColor, tablewriter.Bold}
	case "Minimum":
		return tablewriter.Colors{tablewriter.FgGreenColor, tablewriter.Bold}
	case "Recommended":
		return tablewriter.Colors{tablewriter.FgCyanColor, tablewriter.Bold}
	case "Aspirational":
		return tablewriter.Colors{tablewriter.FgHiYellowColor, tablewriter.Bold}
	default:
		return tablewriter.Colors{}
	}
}
