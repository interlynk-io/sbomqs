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

package reporter

import (
	"context"
	"log"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
)

type Reporter struct {
	Ctx context.Context

	Docs   []sbom.Document
	Scores []scorer.Scores
	Paths  []string

	// optional params
	Format string
	Color  bool
}

var ReportFormats = []string{"basic", "detailed", "json"}

type Option func(r *Reporter)

func WithFormat(c string) Option {
	return func(r *Reporter) {
		r.Format = c
	}
}

func WithColor(c bool) Option {
	return func(r *Reporter) {
		r.Color = c
	}
}

func NewReport(ctx context.Context, doc []sbom.Document, scores []scorer.Scores, paths []string, opts ...Option) *Reporter {
	r := &Reporter{
		Ctx:    ctx,
		Docs:   doc,
		Scores: scores,
		Paths:  paths,
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func (r *Reporter) Report() {
	if r.Format == "basic" {
		r.simpleReport()
	} else if r.Format == "detailed" {
		r.detailedReport()
	} else if r.Format == "json" {
		_, err := r.jsonReport(false)
		if err != nil {
			log.Printf("Failed to print json report: %v", err)
		}
	} else {
		r.detailedReport()
	}
}

func (r *Reporter) ShareReport() (string, error) {
	return r.jsonReport(true)
}
