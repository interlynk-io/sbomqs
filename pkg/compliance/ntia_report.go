package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var ntiaSectionDetails = map[int]ntiaSection{
	SBOM_MACHINE_FORMAT: {Title: "Automation Support", Id: "1.1", Required: true, DataField: "Machine-Readable Formats"},
	SBOM_CREATOR:        {Title: "Required fields sboms ", Id: "2.1", Required: true, DataField: "Author"},
	SBOM_TIMESTAMP:      {Title: "Required fields sboms", Id: "2.2", Required: true, DataField: "Timestamp"},
	SBOM_COMPONENTS:     {Title: "Required sbom component", Id: "2.3", Required: true, DataField: "Packages"},
	COMP_NAME:           {Title: "Required fields components", Id: "2.4", Required: true, DataField: "Package Name"},
	COMP_DEPTH:          {Title: "Required fields components", Id: "2.5", Required: true, DataField: "Dependencies on other components"},
	COMP_CREATOR:        {Title: "Required fields component", Id: "2.6", Required: true, DataField: "Package Supplier"},
	PACK_SUPPLIER:       {Title: "Required fields component", Id: "2.6", Required: true, DataField: "Package Supplier"},
	COMP_VERSION:        {Title: "Required fields components", Id: "2.7", Required: true, DataField: "Package Version"},
	COMP_OTHER_UNIQ_IDS: {Title: "Required fields component", Id: "2.8", Required: true, DataField: "Other Uniq IDs"},
}

type ntiaSection struct {
	Title         string  `json:"section_title"`
	Id            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementId     string  `json:"element_id"`
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

func newNtiaJsonReport() *ntiaComplianceReport {
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

func ntiaJsonReport(db *db, fileName string) {
	jr := newNtiaJsonReport()
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

func ntiaConstructSections(db *db) []ntiaSection {
	var sections []ntiaSection
	allIds := db.getAllIDs()
	for _, id := range allIds {
		records := db.getRecordsByID(id)

		for _, r := range records {
			section := ntiaSectionDetails[r.checkKey]
			new_section := ntiaSection{
				Title:     section.Title,
				Id:        section.Id,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := ntiaKeyIdScore(db, r.checkKey, r.id)
			new_section.Score = score.totalScore()
			if r.id == "doc" {
				new_section.ElementId = "sbom"
			} else {
				new_section.ElementId = r.id
			}

			new_section.ElementResult = r.checkValue

			sections = append(sections, new_section)
		}
	}
	return sections
}

func ntiaDetailedReport(db *db, fileName string) {
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
		if sections[i].ElementId == sections[j].ElementId {
			return sections[i].Id < sections[j].Id
		}
		return sections[i].ElementId < sections[j].ElementId
	})

	for _, section := range sections {
		sectionId := section.Id
		if !section.Required {
			sectionId = sectionId + "*"
		}
		table.Append([]string{section.ElementId, sectionId, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
	}
	table.Render()
}

func ntiaBasicReport(db *db, fileName string) {
	score := ntiaAggregateScore(db)
	fmt.Printf("NTIA Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
