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
	"time"

	"github.com/google/uuid"
	"sigs.k8s.io/release-utils/version"
)

// type compr struct {
// 	Category string  `json:"category"`
// 	Feature  string  `json:"feature"`
// 	Score    float64 `json:"score"`
// 	Desc     string  `json:"description"`
// 	Ignored  bool    `json:"ignored"`
// }

type comprJSON struct {
	Category string        `json:"category"`
	Score    float64       `json:"score"`
	Grade    string        `json:"grade"`
	Weight   float64       `json:"weight"`
	Features []*catFeature `json:"features"`
}

type catFeature struct {
	Key     string  `json:"key"`
	Score   float64 `json:"score"`
	Desc    string  `json:"description"`
	Ignored bool    `json:"ignored"`
}

type profileFeature struct {
	Key        string  `json:"key"`
	Score      float64 `json:"score"`
	Desc       string  `json:"description"`
	Ignored    bool    `json:"ignored"`
	Required   bool    `json:"required"`
	Additional bool    `json:"additional,omitempty"`
}

type profileJSON struct {
	Profile  string            `json:"profile"`
	Score    float64           `json:"score"`
	Grade    string            `json:"grade"`
	Message  string            `json:"message"`
	Features []*profileFeature `json:"features,omitempty"`
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

	Comprehenssive []*comprJSON   `json:"comprehenssive"`
	Profiles       []*profileJSON `json:"profiles"`
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
				cj := &comprJSON{
					Category: cat.Name,
					Score:    cat.Score,
					Grade:    cat.Grade,
					Weight:   cat.Weight,
					Features: make([]*catFeature, 0, len(cat.Features)),
				}

				for _, a := range cat.Features {
					pf := &catFeature{
						Key:     a.Key,
						Score:   a.Score,
						Desc:    a.Desc,
						Ignored: a.Ignored,
						// Required:   a.Required,
						// Additional: a.Additional,
					}
					cj.Features = append(cj.Features, pf)
					// f.Comprehenssive = append(f.Comprehenssive, ns)
				}
				f.Comprehenssive = append(f.Comprehenssive, cj)

			}
		}

		// Handle profile results if present
		if r.Profiles != nil {
			// profiles-only mode: include per-profile feature details
			// both mode (comprehensive + profiles): summary only, no features
			profilesOnly := r.Comprehensive == nil
			for _, pr := range r.Profiles.ProfResult {
				pj := &profileJSON{
					Profile: pr.Name,
					Score:   pr.InterlynkScore,
					Grade:   pr.Grade,
					Message: pr.Message,
				}
				if profilesOnly {
					pj.Features = make([]*profileFeature, 0, len(pr.Items))
					for _, a := range pr.Items {
						pf := &profileFeature{
							Key:        a.Key,
							Score:      a.Score,
							Desc:       a.Desc,
							Ignored:    a.Ignore,
							Required:   a.Required,
							Additional: a.Additional,
						}
						pj.Features = append(pj.Features, pf)
					}
				}
				f.Profiles = append(f.Profiles, pj)
			}

			// If no comprehensive score, use aggregate of profile scores for top-level
			if r.Comprehensive == nil && len(r.Profiles.ProfResult) > 0 {
				f.InterlynkScore = r.Profiles.ProfResult[0].InterlynkScore
				f.Grade = r.Profiles.ProfResult[0].Grade
			}
		}

		jr.Files = append(jr.Files, f)
	}

	o, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return "", err
	}

	return string(o), nil
}
