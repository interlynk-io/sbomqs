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

// Scores represent list of all the score
type Scores interface {
	Count() int
	AvgScore() float64
	ScoreList() []Score
}

type scores struct {
	scs []Score
}

func newScores() *scores {
	return &scores{
		scs: []Score{},
	}
}

func (s *scores) addScore(ss score) {
	s.scs = append(s.scs, ss)
}

func (s scores) Count() int {
	return len(s.scs)
}

// total score is the sum of all scores divided by the number of scores
func (s scores) AvgScore() float64 {
	score := 0.0
	for _, s := range s.scs {
		if !s.Ignore() {
			score += s.Score()
		}
	}
	return score / float64(s.Count())
}

func (s scores) ScoreList() []Score {
	return s.scs
}
