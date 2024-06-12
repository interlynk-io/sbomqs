package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var octSectionDetails = map[int]octSection{
	SBOM_SPEC:         {Title: "DataFormat", Id: "3.1", Required: true, DataField: "SBOM data format"},
	SBOM_SPEC_VERSION: {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Spec version"},
	SBOM_SPDXID:       {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Spec SPDXID"},
	SBOM_ORG:          {Title: "SPDX elements", Id: "4", Required: true, DataField: "SBOM creator organization"},
	SBOM_COMMENT:      {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM creator comment"},
	SBOM_NAMESPACE:    {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM namespace"},
	SBOM_LICENSE:      {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM license"},
	SBOM_NAME:         {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM name"},
	SBOM_TIMESTAMP:    {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM timestamp"},
	SBOM_CREATOR:      {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "SBOM creator"},
	SBOM_TOOL:         {Title: "SPDX elements", Id: "4", Required: true, DataField: "SBOM creator tool"},
	// SBOM_PACKAGES:        {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "components"},
	PACK_INFO:            {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package info"},
	PACK_NAME:            {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package name"},
	PACK_SPDXID:          {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package spdxid"},
	PACK_VERSION:         {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package version"},
	PACK_FILE_ANALYZED:   {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "File Analyze component"},
	PACK_DOWNLOAD_URL:    {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package download URL"},
	PACK_HASH:            {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package checksum"},
	PACK_SUPPLIER:        {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package supplier"},
	PACK_LICENSE_CON:     {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package Concluded License"},
	PACK_LICENSE_DEC:     {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package Declared License"},
	PACK_COPYRIGHT:       {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package copyright"},
	PACK_EXT_REF:         {Title: "SPDX elements", Id: "3.2", Required: true, DataField: "Package external References"},
	SBOM_MACHINE_FORMAT:  {Title: "Machine Readable Data Format", Id: "3.3", Required: true, DataField: "SBOM machine readable format"},
	SBOM_HUMAN_FORMAT:    {Title: "Human Readable Data Format", Id: "3.4", Required: true, DataField: "SBOM human readable format"},
	SBOM_BUILD_INFO:      {Title: "SBOM Build Information", Id: "3.5", Required: true, DataField: "SBOM Creator field"},
	SBOM_DELIVERY_TIME:   {Title: "Timing of SBOM delivery", Id: "3.6", Required: true, DataField: "SBOM delivery time"},
	SBOM_DELIVERY_METHOD: {Title: "Method of SBOM delivery", Id: "3.7", Required: true, DataField: "SBOM delivery method"},
	SBOM_SCOPE:           {Title: "SBOM Scope", Id: "3.8", Required: true, DataField: "SBOM scope"},
}

type octSection struct {
	Title         string  `json:"section_title"`
	Id            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementId     string  `json:"element_id"`
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

func newOctJsonReport() *octComplianceReport {
	return &octComplianceReport{
		Name:     "Open Chain Telco Report",
		Subtitle: "Part 2: Software Bill of Materials (SBOM)",
		Revision: "",
		Run: run{
			Id:            uuid.New().String(),
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

func octJsonReport(db *db, fileName string) {
	jr := newOctJsonReport()
	jr.Run.FileName = fileName

	score := octAggregateScore(db)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = octConstructSections(db)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func octConstructSections(db *db) []octSection {
	var sections []octSection
	allIds := db.getAllIds()
	for _, id := range allIds {
		records := db.getRecordsById(id)

		for _, r := range records {
			section := octSectionDetails[r.check_key]
			new_section := octSection{
				Title:     section.Title,
				Id:        section.Id,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := octKeyIdScore(db, r.check_key, r.id)
			new_section.Score = score.totalScore()
			if r.id == "doc" {
				new_section.ElementId = "sbom"
			} else {
				new_section.ElementId = r.id
			}

			new_section.ElementResult = r.check_value

			sections = append(sections, new_section)
		}
	}
	return sections
}

func octDetailedReport(db *db, fileName string) {
	table := tablewriter.NewWriter(os.Stdout)
	score := octAggregateScore(db)

	fmt.Printf("OpenChain Telco Report\n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ElementId", "Section", "Datafield", "Element Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := octConstructSections(db)
	for _, section := range sections {
		sectionId := section.Id
		if !section.Required {
			sectionId = sectionId + "*"
		}
		table.Append([]string{section.ElementId, sectionId, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
	}
	table.Render()
}

func octBasicReport(db *db, fileName string) {
	score := octAggregateScore(db)
	fmt.Printf("Cyber Resilience Requirements for Manufacturers and Products Report TR-03183-2 (1.1)\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
