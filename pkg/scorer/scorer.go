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

package scorer

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

const EngineVersion = "7"

type filterType int

const (
	Feature filterType = iota
	Category
)

type Filter struct {
	Name  string
	Ftype filterType
}

type Scorer struct {
	ctx context.Context
	doc sbom.Document

	// optional params
	featFilter map[string]bool
	catFilter  map[string]bool
}

func NewScorer(ctx context.Context, doc sbom.Document) *Scorer {
	scorer := &Scorer{
		ctx:        ctx,
		doc:        doc,
		featFilter: make(map[string]bool),
		catFilter:  make(map[string]bool),
	}

	return scorer
}

func (s *Scorer) AddFilter(nm string, ftype filterType) {
	switch ftype {
	case Feature:
		s.featFilter[nm] = true
	case Category:
		s.catFilter[nm] = true
	}
}

func (s *Scorer) Score() Scores {
	if s.doc == nil {
		return newScores()
	}

	if len(s.featFilter) > 0 {
		return s.featureScores()
	}

	if len(s.catFilter) > 0 {
		return s.catScores()
	}

	return s.AllScores()
}

func (s *Scorer) catScores() Scores {
	scores := newScores()

	for _, c := range checks {
		cCopy := c // Create a copy of c
		if s.catFilter[c.Category] {
			scores.addScore(c.evaluate(s.doc, &cCopy))
		}
	}

	return scores
}

func (s *Scorer) featureScores() Scores {
	scores := newScores()

	for _, c := range checks {
		if s.featFilter[c.Key] {
			scores.addScore(c.evaluate(s.doc, &c)) //nolint:gosec
		}
	}

	return scores
}

func (s *Scorer) AllScores() Scores {
	scores := newScores()

	for _, c := range checks {
		scores.addScore(c.evaluate(s.doc, &c)) //nolint:gosec
	}

	return scores
}
