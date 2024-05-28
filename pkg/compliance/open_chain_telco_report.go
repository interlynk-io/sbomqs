// Copyright 2024 riteshnoronha
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
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var openChainTelcoSectionDetails = map[int]octSection{
	OCT_SBOM_SPEC:            {Title: "SBOM formats", Id: "3.1", Required: true, DataField: "data format"},
	OCT_SPEC_VERSION:         {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "specification version"},
	OCT_DOC_DATA_LICENSE:         {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document data license"},
	OCT_DOC_SPDXID:           {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document SPDX ID"},
	OCT_DOC_NAME:			 {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document name"},
	OCT_DOC_NAMESPACE:        {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document namespace"},
	OCT_DOC_CREATOR:		  {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document creator"},
	OCT_DOC_CREATED:          {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document created"},
	OCT_DOC_LIFECYCLE:        {Title: "SPDX Elements", Id: "3.2", Required: true, DataField: "document lifecycle"},
	OCT_PKG_NAME:			 {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package name"},
	OCT_PKG_VERSION:          {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package version"},
	OCT_PKG_SPDXID:           {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package SPDX ID"},
	OCT_PKG_SUPPLIER:         {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package supplier"},
	OCT_PKG_DOWNLOAD_LOCATION:{Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package download location"},
	OCT_PKG_FILES_ANALYZED:   {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "files analyzed"},
	OCT_PKG_CHECKSUM:         {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package checksum"},
	OCT_PKG_LICENSE_CONCLUDED:{Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package license concluded"},
	OCT_PKG_LICENSE_DECLARED: {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package license declared"},
	OCT_PKG_COPYRIGHT:        {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package copyright"},
	OCT_PKG_PURL:             {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package PURL"},
	OCT_PKG_RELATIONSHIP:     {Title: "SPDX Package Information", Id: "3.2", Required: true, DataField: "package relationship"},
	OCT_DOC_FILE_FORMAT:	  {Title: "Machine Readable Data Format", Id: "3.3", Required: true, DataField: "document file format"},
	OCT_DOC_HUMAN_FILE_FORMAT:{Title: "Human Readable Data Format", Id: "3.4", Required: true, DataField: "document human file format"},
	OCT_SBOM_SCOPE:           {Title: "SBOM Scope", Id: "3.8", Required: true, DataField: "sbom scope"},
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
	Sections []craSection `json:"sections"`
}

func newOctJsonReport() *octComplianceReport {
	return &octComplianceReport{
		Name:     "OpenChain Telco SBOM Guide Version 1.0",
		Subtitle: "SBOM guide",
		Revision: "v1.0",
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

	score := craAggregateScore(db)
	summary := Summary{}
	summary.MaxScore = 10.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = constructSections(db)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}



