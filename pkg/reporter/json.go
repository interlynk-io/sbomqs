// Copyright 2023 Interlynk.io
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

package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"sigs.k8s.io/release-utils/version"
)

type score struct {
	Category string  `json:"category"`
	Feature  string  `json:"feature"`
	Score    float64 `json:"score"`
	MaxScore float64 `json:"max_score"`
	Desc     string  `json:"description"`
	Ignored  bool    `json:"ignored"`
}
type file struct {
	Name        string   `json:"file_name"`
	Spec        string   `json:"spec"`
	SpecVersion string   `json:"spec_version"`
	Format      string   `json:"file_format"`
	AvgScore    float64  `json:"avg_score"`
	Components  int      `json:"num_components"`
	Scores      []*score `json:"scores"`
}

type creation struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	ScoringEngine string `json:"scoring_engine_version"`
}

type jsonReport struct {
	RunID        string   `json:"run_id"`
	TimeStamp    string   `json:"timestamp"`
	CreationInfo creation `json:"creation_info"`
	Files        []file   `json:"files"`
}

func newJsonReport() *jsonReport {
	return &jsonReport{
		RunID:     uuid.New().String(),
		TimeStamp: time.Now().UTC().Format(time.RFC3339),
		CreationInfo: creation{
			Name:          "sbomqs",
			Version:       version.GetVersionInfo().GitVersion,
			ScoringEngine: scorer.EngineVersion,
		},
		Files: []file{},
	}
}

func (r *Reporter) jsonReport() {
	jr := newJsonReport()
	for index, path := range r.Paths {
		doc := r.Docs[index]
		scores := r.Scores[index]

		f := file{}
		f.AvgScore = scores.AvgScore()
		f.Components = len(doc.Components())
		f.Format = doc.Spec().FileFormat()
		f.Name = path
		f.Spec = doc.Spec().Name()
		f.SpecVersion = doc.Spec().Version()

		for _, ss := range scores.ScoreList() {
			ns := new(score)
			ns.Category = ss.Category()
			ns.Feature = ss.Feature()
			ns.Score = ss.Score()
			ns.MaxScore = ss.MaxScore()
			ns.Desc = ss.Descr()
			ns.Ignored = ss.Ignore()

			f.Scores = append(f.Scores, ns)
		}

		jr.Files = append(jr.Files, f)
	}
	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}
