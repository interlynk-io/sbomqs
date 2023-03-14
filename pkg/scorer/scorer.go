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

package scorer

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

const EngineVersion = "4"

type Scorer struct {
	ctx context.Context
	doc sbom.Document

	//optional params
	category string
	feature  []string
}

type Option func(s *Scorer)

func WithCategory(c string) Option {
	return func(s *Scorer) {
		s.category = c
	}
}

func WithFeature(f []string) Option {
	return func(s *Scorer) {
		s.feature = f
	}
}

func NewScorer(ctx context.Context, doc sbom.Document, opts ...Option) *Scorer {
	scorer := &Scorer{
		ctx: ctx,
		doc: doc,
	}

	for _, opt := range opts {
		opt(scorer)
	}
	return scorer
}

func (s *Scorer) Score() Scores {
	_ = logger.FromContext(s.ctx)

	if s.doc == nil {
		return newScores()
	}
	scores := newScores()

	for key, cr := range criteria {
		score := cr(s.doc)
		if len(s.feature) > 0 {
			if lo.Contains(s.feature, string(key)) {
				scoreFilterWithCategory(score, scores)
			}
		} else {
			scoreFilterWithCategory(score, scores)
		}
	}
	return scores
}

func scoreFilterWithCategory(s score, ss *scores) {
	if s.category != "" && s.category == s.Category() {
		ss.addScore(s)
	} else if s.category == "" {
		ss.addScore(s)
	}
}
