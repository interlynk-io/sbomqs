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
	"time"

	"github.com/google/uuid"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var bsiSectionDetails = map[int]bsiSection{
	SBOM_SPEC:            {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification"},
	SBOM_SPEC_VERSION:    {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification version"},
	SBOM_BUILD:           {Title: "Level of Detail", ID: "5.1", Required: true, DataField: "build process"},
	SBOM_DEPTH:           {Title: "Level of Detail", ID: "5.1", Required: true, DataField: "depth"},
	SBOM_CREATOR:         {Title: "Required fields sboms ", ID: "5.2.1", Required: true, DataField: "creator of sbom"},
	SBOM_TIMESTAMP:       {Title: "Required fields sboms", ID: "5.2.1", Required: true, DataField: "timestamp"},
	SBOM_COMPONENTS:      {Title: "Required fields component", ID: "5.2.2", Required: true, DataField: "components"},
	SBOM_URI:             {Title: "Additional fields sboms", ID: "5.3.1", Required: false, DataField: "SBOM-URI"},
	COMP_CREATOR:         {Title: "Required fields component", ID: "5.2.2", Required: true, DataField: "component creator"},
	COMP_NAME:            {Title: "Required fields components", ID: "5.2.2", Required: true, DataField: "component name"},
	COMP_VERSION:         {Title: "Required fields components", ID: "5.2.2", Required: true, DataField: "component version"},
	COMP_DEPTH:           {Title: "Required fields components", ID: "5.2.2", Required: true, DataField: "Dependencies on other components"},
	COMP_LICENSE:         {Title: "Required fields components", ID: "5.2.2", Required: true, DataField: "License"},
	COMP_HASH:            {Title: "Required fields components", ID: "5.2.2", Required: true, DataField: "Hash value of the executable component"},
	COMP_SOURCE_CODE_URL: {Title: "Additional fields components", ID: "5.3.2", Required: false, DataField: "Source code URI"},
	COMP_DOWNLOAD_URL:    {Title: "Additional fields components", ID: "5.3.2", Required: false, DataField: "URI of the executable form of the component"},
	COMP_SOURCE_HASH:     {Title: "Additional fields components", ID: "5.3.2", Required: false, DataField: "Hash value of the source code of the component"},
	COMP_OTHER_UNIQ_IDS:  {Title: "Additional fields components", ID: "5.3.2", Required: false, DataField: "Other unique identifiers"},
	SBOM_VULNERABILITES:  {Title: "Definition of SBOM", ID: "3.1", Required: true, DataField: "vuln"},
	COMP_FILENAMES:       {Title: "Required sboms fields", ID: "5.2.2", Required: true, DataField: "filename"},
	COMP_ARCHIVE_FILE:    {Title: "Required sboms fields", ID: "5.2.2", Required: true, DataField: "archive"},
	COMP_EXECUTABLE_FILE: {Title: "Required sboms fields", ID: "5.2.2", Required: true, DataField: "executable"},
	COMP_STRUCTURED_FILE: {Title: "Required sboms fields", ID: "5.2.2", Required: true, DataField: "structured"},
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
	TotalScore         float64 `json:"total_score"`
	MaxScore           float64 `json:"max_score"`
	TotalRequiredScore float64 `json:"required_elements_score"`
	TotalOptionalScore float64 `json:"optional_elements_score"`
}
type bsiSection struct {
	Title         string  `json:"section_title"`
	ID            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementID     string  `json:"element_id"`
	ElementResult string  `json:"element_result"`
	Score         float64 `json:"score"`
}
type bsiComplianceReport struct {
	Name     string       `json:"report_name"`
	Subtitle string       `json:"subtitle"`
	Revision string       `json:"revision"`
	Run      run          `json:"run"`
	Tool     tool         `json:"tool"`
	Summary  Summary      `json:"summary"`
	Sections []bsiSection `json:"sections"`
}

func newJSONReport(name, revision string) *bsiComplianceReport {
	return &bsiComplianceReport{
		Name:     name,
		Subtitle: "Part 2: Software Bill of Materials (SBOM)",
		Revision: revision,
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

func bsiJSONReport(dtb *db.DB, fileName string) {
	name := "BSI TR-03183-2 v1.1 Compliance Report"
	revision := "TR-03183-2 (1.1)"
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

func constructSections(dtb *db.DB) []bsiSection {
	var sections []bsiSection
	allIDs := dtb.GetAllIDs()
	for _, id := range allIDs {
		records := dtb.GetRecordsByID(id)

		for _, r := range records {
			section := bsiSectionDetails[r.CheckKey]
			newSection := bsiSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := bsiKeyIDScore(dtb, r.CheckKey, r.ID)
			newSection.Score = score.totalScore()
			if r.ID == "doc" {
				newSection.ElementID = "SBOM"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}
	// Group sections by ElementID
	sectionsByElementID := make(map[string][]bsiSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	// Sort each group of sections by section.ID and ensure "SBOM" comes first within its group if it exists
	var sortedSections []bsiSection
	var sbomLevelSections []bsiSection
	for elementID, group := range sectionsByElementID {
		if elementID == "SBOM" {
			sbomLevelSections = group
		} else {
			sortedSections = append(sortedSections, group...)
		}
	}

	// Place "SBOM Level" sections at the top
	sortedSections = append(sbomLevelSections, sortedSections...)

	return sortedSections
}

func bsiDetailedReport(dtb *db.DB, fileName string) {
	table := tablewriter.NewWriter(os.Stdout)
	score := bsiAggregateScore(dtb)

	fmt.Printf("BSI TR-03183-2 v1.1 Compliance Report \n")
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

func bsiBasicReport(dtb *db.DB, fileName string) {
	score := bsiAggregateScore(dtb)
	fmt.Printf("BSI TR-03183-2 v1.1 Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
