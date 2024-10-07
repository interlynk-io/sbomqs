package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var octSectionDetails = map[int]octSection{
	SBOM_SPEC:            {Title: "SBOM Format", ID: "3.1.1", Required: true, DataField: "SBOM data format"},
	SBOM_SPEC_VERSION:    {Title: "SPDX Elements", ID: "3.1.2", Required: true, DataField: "Spec version"},
	SBOM_SPDXID:          {Title: "SPDX Elements", ID: "3.1.3", Required: true, DataField: "Spec spdxid"},
	SBOM_ORG:             {Title: "SBOM Build Information", ID: "3.1.4", Required: true, DataField: "SBOM creator organization"},
	SBOM_COMMENT:         {Title: "SPDX Elements", ID: "3.1.5", Required: true, DataField: "SBOM creator comment"},
	SBOM_NAMESPACE:       {Title: "SPDX Elements", ID: "3.1.6", Required: true, DataField: "SBOM namespace"},
	SBOM_LICENSE:         {Title: "SPDX Elements", ID: "3.1.7", Required: true, DataField: "SBOM license"},
	SBOM_NAME:            {Title: "SPDX Elements", ID: "3.1.8", Required: true, DataField: "SBOM name"},
	SBOM_TIMESTAMP:       {Title: "SPDX Elements", ID: "3.1.9", Required: true, DataField: "SBOM timestamp"},
	SBOM_TOOL:            {Title: "SBOM Build Information", ID: "3.1.10", Required: true, DataField: "SBOM creator tool"},
	SBOM_MACHINE_FORMAT:  {Title: "Machine Readable Data Format", ID: "3.1.11", Required: true, DataField: "SBOM machine readable format"},
	SBOM_HUMAN_FORMAT:    {Title: "Human Readable Data Format", ID: "3.1.12", Required: true, DataField: "SBOM human readable format"},
	SBOM_BUILD_INFO:      {Title: "SBOM Build Information", ID: "3.1.13", Required: true, DataField: "SBOM creator field"},
	SBOM_DELIVERY_TIME:   {Title: "Timing of SBOM delivery", ID: "3.1.14", Required: true, DataField: "SBOM delivery time"},
	SBOM_DELIVERY_METHOD: {Title: "Method of SBOM delivery", ID: "3.1.15", Required: true, DataField: "SBOM delivery method"},
	SBOM_SCOPE:           {Title: "SBOM Scope", ID: "3.1.16", Required: true, DataField: "SBOM scope"},

	PACK_INFO:          {Title: "SPDX Elements", ID: "3.2.1", Required: true, DataField: "Package info"},
	PACK_NAME:          {Title: "SPDX Elements", ID: "3.2.2", Required: true, DataField: "Package name"},
	PACK_SPDXID:        {Title: "SPDX Elements", ID: "3.2.3", Required: true, DataField: "Package spdxid"},
	PACK_VERSION:       {Title: "SPDX Elements", ID: "3.2.4", Required: true, DataField: "Package version"},
	PACK_FILE_ANALYZED: {Title: "SPDX Elements", ID: "3.2.5", Required: true, DataField: "FileAnalyze"},
	PACK_DOWNLOAD_URL:  {Title: "SPDX Elements", ID: "3.2.6", Required: true, DataField: "Package download URL"},
	PACK_HASH:          {Title: "SPDX Elements", ID: "3.2.7", Required: true, DataField: "Package checksum"},
	PACK_SUPPLIER:      {Title: "SPDX Elements", ID: "3.2.8", Required: true, DataField: "Package supplier"},
	PACK_LICENSE_CON:   {Title: "SPDX Elements", ID: "3.2.9", Required: true, DataField: "Package concluded License"},
	PACK_LICENSE_DEC:   {Title: "SPDX Elements", ID: "3.2.10", Required: true, DataField: "Package declared License"},
	PACK_COPYRIGHT:     {Title: "SPDX Elements", ID: "3.2.11", Required: true, DataField: "Package copyright"},
	PACK_EXT_REF:       {Title: "SPDX Elements", ID: "3.2.12", Required: true, DataField: "Package external References"},
}

type octSection struct {
	Title         string  `json:"section_title"`
	ID            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementID     string  `json:"element_id"`
	ElementResult string  `json:"element_result"`
	Score         float64 `json:"score"`
}

type octComplianceReport struct {
	Name     string       `json:"report_name"`
	Subtitle string       `json:"subtitle"`
	Revision string       `json:"revision"`
	Run      run          `json:"run"`
	Tool     tool         `json:"tool"`
	Summary  Summary      `json:"summary"`
	Sections []octSection `json:"sections"`
}

func newOctJSONReport() *octComplianceReport {
	return &octComplianceReport{
		Name:     "Open Chain Telco Report",
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

func octJSONReport(dtb *db.DB, fileName string) {
	jr := newOctJSONReport()
	jr.Run.FileName = fileName

	score := octAggregateScore(dtb)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = octConstructSections(dtb)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func octConstructSections(dtb *db.DB) []octSection {
	var sections []octSection
	allIDs := dtb.GetAllIDs()
	for _, id := range allIDs {
		records := dtb.GetRecordsByID(id)

		for _, r := range records {
			section := octSectionDetails[r.CheckKey]
			newSection := octSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := octKeyIDScore(dtb, r.CheckKey, r.ID)
			newSection.Score = score.totalScore()
			if r.ID == "SPDX Elements" {
				newSection.ElementID = "SPDX Elements"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}
	// Group sections by ElementID
	sectionsByElementID := make(map[string][]octSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	// Sort each group of sections by section.ID and ensure "SPDX Elements" comes first within its group if it exists
	var sortedSections []octSection
	var sbomLevelSections []octSection
	for elementID, group := range sectionsByElementID {
		sort.Slice(group, func(i, j int) bool {
			return group[i].ID < group[j].ID
		})
		if elementID == "SPDX Elements" {
			sbomLevelSections = group
		} else {
			sortedSections = append(sortedSections, group...)
		}
	}

	// Place "SBOM Level" sections at the top
	sortedSections = append(sbomLevelSections, sortedSections...)

	return sortedSections
}

func octDetailedReport(dtb *db.DB, fileName string) {
	table := tablewriter.NewWriter(os.Stdout)
	score := octAggregateScore(dtb)

	fmt.Printf("OpenChain Telco Report\n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := octConstructSections(dtb)
	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID = sectionID + "*"
		}
		table.Append([]string{section.ElementID, sectionID, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
	}
	table.Render()
}

func octBasicReport(dtb *db.DB, fileName string) {
	score := octAggregateScore(dtb)
	fmt.Printf("OpenChain Telco Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
