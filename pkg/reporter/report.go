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
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/olekukonko/tablewriter"
)

type Reporter struct {
	ctx    context.Context
	doc    sbom.Document
	scores scorer.Scores

	//optional params
	format   string
	filePath string
}

var ReportFormats = []string{"basic", "detailed"}

type Option func(r *Reporter)

func WithFormat(c string) Option {
	return func(r *Reporter) {
		r.format = c
	}
}

func WithFilePath(c string) Option {
	return func(r *Reporter) {
		r.filePath = c
	}
}

func NewReport(ctx context.Context, doc sbom.Document, scores scorer.Scores, opts ...Option) *Reporter {
	r := &Reporter{
		ctx:    ctx,
		doc:    doc,
		scores: scores,
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Reporter) Report() {
	if r.format == "basic" {
		r.simpleReport()
	} else if r.format == "detailed" {
		r.detailedReport()
	} else {
		r.detailedReport()
	}

}

func (r *Reporter) simpleReport() {
	fmt.Printf("%0.1f\t%s\n", r.scores.AvgScore(), r.filePath)
}

func (r *Reporter) detailedReport() {

	outDoc := [][]string{}

	for _, score := range r.scores.ScoreList() {
		l := []string{score.Category(), score.Feature(), fmt.Sprintf("%0.1f/10.0", score.Score()), score.Descr()}
		outDoc = append(outDoc, l)
	}

	sort.Slice(outDoc, func(i, j int) bool {
		return outDoc[i][0] < outDoc[j][0]
	})

	fmt.Printf("SBOM Quality Score: %0.1f\t%s\n", r.scores.AvgScore(), r.filePath)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Category", "Feature", "Score", "Desc"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	table.AppendBulk(outDoc)
	table.Render()

}
