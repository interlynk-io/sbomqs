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

type ScvsScore interface {
	Feature() string
	Score() string
}

type scvsScore struct {
	feature string
	score   string
}

func newScoreFromScvsCheck(c *scvsCheck) *scvsScore {
	return &scvsScore{
		feature: c.Key,
	}
}

func (s *scvsScore) setScore(v string) {
	s.score = v
}

func (s scvsScore) Feature() string {
	return s.feature
}

func (s scvsScore) Score() string {
	return s.score
}
