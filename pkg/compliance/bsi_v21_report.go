// Copyright 2025 Interlynk.io
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

	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
)

var bsiV21SectionDetails = map[int]bsiSection{
	SBOM_SPEC:              {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification"},
	SBOM_SPEC_VERSION:      {Title: "SBOM formats", ID: "4", Required: true, DataField: "specification version"},
	SBOM_BUILD:             {Title: "Level of Detail", ID: "5.1", Required: true, DataField: "build process"},
	SBOM_DEPTH:             {Title: "Level of Detail", ID: "5.2.1", Required: true, DataField: "dependency graph completeness"},
	SBOM_CREATOR:           {Title: "Required SBOM fields", ID: "5.2.1", Required: true, DataField: "creator of SBOM"},
	SBOM_TIMESTAMP:         {Title: "Required SBOM fields", ID: "5.2.1", Required: true, DataField: "timestamp"},
	SBOM_URI:               {Title: "Required SBOM fields", ID: "5.2.1", Required: true, DataField: "SBOM-URI"},
	SBOM_COMPONENTS:        {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "components"},
	SBOM_VULNERABILITIES:   {Title: "Definition of SBOM", ID: "3.1", Required: true, DataField: "vuln"},
	COMP_CREATOR:           {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "component creator"},
	COMP_NAME:              {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "component name"},
	COMP_VERSION:           {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "component version"},
	COMP_FILENAME:          {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "filename"},
	COMP_DEPTH:             {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "dependencies"},
	COMP_CONCLUDED_LICENSE: {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "distribution licence (concluded)"},
	COMP_DEPLOYABLE_HASH:   {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "hash of deployable component"},
	COMP_EXECUTABLE:        {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "executable property"},
	COMP_ARCHIVE:           {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "archive property"},
	COMP_STRUCTURED:        {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "structured property"},
	COMP_SOURCE_CODE_URL:   {Title: "Required component fields", ID: "5.2.3", Required: true, DataField: "source code URI"},
	COMP_DOWNLOAD_URL:      {Title: "Required component fields", ID: "5.2.4", Required: true, DataField: "URI of deployable form"},
	COMP_OTHER_UNIQ_IDS:    {Title: "Required component fields", ID: "5.2.5", Required: true, DataField: "other unique identifiers"},
	COMP_DECLARED_LICENSE:  {Title: "Required component fields", ID: "5.2.2", Required: true, DataField: "original licence (declared)"},
	COMP_EFFECTIVE_LICENSE: {Title: "Optional component fields", ID: "5.2.3", Required: false, DataField: "effective licence"},
	COMP_SOURCE_HASH:       {Title: "Optional component fields", ID: "5.2.3", Required: false, DataField: "hash of source code"},
	COMP_SECURITY_TXT_URL:  {Title: "Optional component fields", ID: "5.2.3", Required: false, DataField: "security.txt URL"},
}

func bsiV21JSONReport(dtb *db.DB, fileName string) {
	name := "BSI TR-03183-2 v2.1.0 Compliance Report"
	revision := "TR-03183-2 (2.1.0)"
	jr := newJSONReport(name, revision)
	jr.Run.FileName = fileName

	score := bsiAggregateScore(dtb)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalAdditionalScore = score.totalAdditionalScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = constructV21Sections(dtb)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func bsiV21DetailedReport(dtb *db.DB, fileName string) {
	table := tablewriter.NewWriter(os.Stdout)
	score := bsiAggregateScore(dtb)

	fmt.Printf("BSI TR-03183-2 v2.1.0 Compliance Report \n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f AdditionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalAdditionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := constructV21Sections(dtb)

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID += "*"
		}
		table.Append([]string{section.ElementID, sectionID, section.DataField, wrapResult(section.ElementResult), fmt.Sprintf("%0.1f", section.Score)})
	}
	table.Render()
}

func bsiV21BasicReport(dtb *db.DB, fileName string) {
	score := bsiAggregateScore(dtb)
	fmt.Printf("BSI TR-03183-2 v2.1.0 Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f AdditionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalAdditionalScore(), fileName)
}

func constructV21Sections(dtb *db.DB) []bsiSection {
	allIDs := dtb.GetAllIDs()

	estimatedCapacity := len(allIDs) * 5
	sections := make([]bsiSection, 0, estimatedCapacity)

	for _, id := range allIDs {
		records := dtb.GetRecordsByID(id)

		for _, r := range records {
			section, ok := bsiV21SectionDetails[r.CheckKey]
			if !ok {
				continue
			}
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
