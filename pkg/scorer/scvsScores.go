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

type ScvsScores interface {
	Count() int
	AvgScore() float64
	ScoreList() []ScvsScore
}

type scvsScores struct {
	scs []ScvsScore
}

func newScvsScores() *scvsScores {
	return &scvsScores{
		scs: []ScvsScore{},
	}
}

func (s *scvsScores) addScore(ss scvsScore) {
	s.scs = append(s.scs, ss)
}

func (s scvsScores) Count() int {
	return len(s.scs)
}

func (s scvsScores) AvgScore() float64 {
	score := 0.0
	for _, s := range s.scs {
		if s.L1Score() == "✓" {
			score++
		}
	}
	return score / float64(s.Count())
}

func (s scvsScores) ScoreList() []ScvsScore {
	return s.scs
}
