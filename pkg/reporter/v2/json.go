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

package v2

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"sigs.k8s.io/release-utils/version"
)

type score struct {
	Category string  `json:"category"`
	Feature  string  `json:"feature"`
	Score    float64 `json:"score"`
	Desc     string  `json:"description"`
	Ignored  bool    `json:"ignored"`
}

type file struct {
	Name           string   `json:"file_name"`
	Spec           string   `json:"spec"`
	SpecVersion    string   `json:"spec_version"`
	Format         string   `json:"file_format"`
	Grade          string   `json:"grade"`
	InterlynkScore float64  `json:"interlynk_score"`
	Components     int      `json:"num_components"`
	CreationTime   string   `json:"creation_time"`
	Scores         []*score `json:"scores"`
}

type creation struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SBOMQS_Engine string `json:"sbomqs_engine_version"`
	Vendor        string `json:"vendor"`
}

type jsonReport struct {
	RunID        string   `json:"run_id"`
	TimeStamp    string   `json:"timestamp"`
	CreationInfo creation `json:"creation_info"`
	Files        []file   `json:"files"`
}

func newJSONReport() *jsonReport {
	return &jsonReport{
		RunID:     uuid.New().String(),
		TimeStamp: time.Now().UTC().Format(time.RFC3339),
		CreationInfo: creation{
			Name:          "sbomqs",
			Version:       version.GetVersionInfo().GitVersion,
			SBOMQS_Engine: EngineVersion,
			Vendor:        "Interlynk (support@interlynk.io)",
		},
		Files: []file{},
	}
}

func (r *Reporter) jsonReport() (string, error) {
	jr := newJSONReport()

	for _, r := range r.Results {
		f := file{}
		f.InterlynkScore = r.InterlynkScore
		f.Grade = r.Grade
		f.Components = r.Meta.NumComponents
		f.Format = r.Meta.FileFormat
		f.Name = r.Meta.Filename
		f.Spec = r.Meta.Spec
		f.CreationTime = r.Meta.CreationTime

		if r.Meta.Spec == string(sbom.SBOMSpecSPDX) {
			version := strings.Replace(r.Meta.SpecVersion, "SPDX-", "", 1)
			f.SpecVersion = version
		}

		for _, cat := range r.Comprehensive.CatResult {
			for _, feat := range cat.Features {
				ns := new(score)
				ns.Category = cat.Name
				ns.Feature = feat.Key
				ns.Score = feat.Score
				ns.Desc = feat.Desc
				ns.Ignored = feat.Ignored
				f.Scores = append(f.Scores, ns)
			}
		}

		jr.Files = append(jr.Files, f)
	}

	o, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}

	if true {
		fmt.Println(string(o))
	}

	return string(o), nil
}
