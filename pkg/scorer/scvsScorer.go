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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

type ScvsScorer struct {
	ctx context.Context
	doc sbom.Document
}

func NewScvsScorer(ctx context.Context, doc sbom.Document) *ScvsScorer {
	scorer := &ScvsScorer{
		ctx: ctx,
		doc: doc,
	}

	return scorer
}

func (s *ScvsScorer) ScvsScore() ScvsScores {
	if s.doc == nil {
		return newScvsScores()
	}

	return s.AllScvsScores()
}

func (s *ScvsScorer) AllScvsScores() ScvsScores {
	scores := newScvsScores()

	for _, c := range scvsChecks {
		scores.addScore(c.evaluate(s.doc, &c))
	}

	return scores
}
