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
	"fmt"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

const EngineVersion = "7"

type filterType int

const (
	Feature filterType = iota
	Category
	Mix
)

type Filter struct {
	Name     string
	Ftype    filterType
	Category string
}

type Scorer struct {
	ctx context.Context
	doc sbom.Document

	// optional params
	featFilter map[string]bool
	catFilter  map[string]bool
	mixFilter  map[string]map[string]bool
}

func NewScorer(ctx context.Context, doc sbom.Document) *Scorer {
	scorer := &Scorer{
		ctx:        ctx,
		doc:        doc,
		featFilter: make(map[string]bool),
		catFilter:  make(map[string]bool),
		mixFilter:  make(map[string]map[string]bool),
	}

	return scorer
}

// enable filtering by feature, category, or mix of both
// for scoring checks
func (s *Scorer) AddFilter(f Filter) {
	switch f.Ftype {
	case Feature:
		s.featFilter[f.Name] = true
	case Category:
		s.catFilter[f.Name] = true
	case Mix:
		if s.mixFilter[f.Category] == nil {
			s.mixFilter[f.Category] = make(map[string]bool)
		}
		s.mixFilter[f.Category][f.Name] = true
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

	if len(s.mixFilter) > 0 {
		return s.featureAndCatScores()
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
	fmt.Println("Scoring features with filters:", s.featFilter)
	scores := newScores()

	checkMap := make(map[string]bool)

	for _, c := range checks {
		if _, exists := checkMap[c.Key]; exists {
			continue // Skip if the feature has already been processed
		}
		if s.featFilter[c.Key] {
			scores.addScore(c.evaluate(s.doc, &c)) //nolint:gosec
		}
	}

	return scores
}

// featureAndCatScores returns scores for both features and categories
func (s *Scorer) featureAndCatScores() Scores {
	scores := newScores()

	for _, c := range checks {
		if s.mixFilter[c.Category][c.Key] {
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
