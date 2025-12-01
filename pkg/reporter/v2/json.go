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
	"time"

	"github.com/google/uuid"
	"sigs.k8s.io/release-utils/version"
)

type compr struct {
	Category string  `json:"category"`
	Feature  string  `json:"feature"`
	Score    float64 `json:"score"`
	Desc     string  `json:"description"`
	Ignored  bool    `json:"ignored"`
}

type prof struct {
	Profile string  `json:"profile"`
	Score   float64 `json:"score"`
	Grade   string  `json:"grade"`
	Message string  `json:"message"`
}

type file struct {
	InterlynkScore float64 `json:"sbom_quality_score"`
	Grade          string  `json:"grade"`
	Components     int     `json:"num_components"`
	FileName       string  `json:"file_name"`

	Spec         string `json:"spec"`
	SpecVersion  string `json:"spec_version"`
	Format       string `json:"file_format"`
	CreationTime string `json:"creation_time"`

	Comprehenssive []*compr `json:"comprehenssive"`
	Profiles       []*prof  `json:"profiles"`
}

type creation struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	EngineVersion string `json:"sbomqs_engine_version"`
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
			EngineVersion: EngineVersion,
			Vendor:        "Interlynk (support@interlynk.io)",
		},
		Files: []file{},
	}
}

func (r *Reporter) jsonReport() (string, error) {
	jr := newJSONReport()

	for _, r := range r.Results {
		f := file{}
		f.Components = r.Meta.NumComponents
		f.FileName = r.Meta.Filename
		f.Spec = r.Meta.Spec
		f.SpecVersion = r.Meta.SpecVersion
		f.Format = r.Meta.FileFormat
		f.CreationTime = r.Meta.CreationTime

		// Handle comprehensive results if present
		if r.Comprehensive != nil {
			f.InterlynkScore = r.Comprehensive.InterlynkScore
			f.Grade = r.Comprehensive.Grade

			for _, cat := range r.Comprehensive.CatResult {
				for _, feat := range cat.Features {
					ns := new(compr)
					ns.Category = cat.Name
					ns.Feature = feat.Key
					ns.Score = feat.Score
					ns.Desc = feat.Desc
					ns.Ignored = feat.Ignored
					f.Comprehenssive = append(f.Comprehenssive, ns)
				}
			}
		}

		// Handle profile results if present
		if r.Profiles != nil {
			for _, pr := range r.Profiles.ProfResult {
				p := new(prof)
				p.Profile = pr.Name
				p.Grade = pr.Grade
				p.Score = pr.InterlynkScore
				p.Message = pr.Message

				f.Profiles = append(f.Profiles, p)

				// If no comprehensive score, use first profile score for top-level
				if r.Comprehensive == nil && f.InterlynkScore == 0 {
					f.InterlynkScore = pr.InterlynkScore
					f.Grade = pr.Grade
				}
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
