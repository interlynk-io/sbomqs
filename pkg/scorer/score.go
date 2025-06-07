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

import "math"

type Score interface {
	Category() string
	Feature() string
	Ignore() bool
	Score() float64
	Descr() string
	MaxScore() float64
}

//nolint:revive,stylecheck
const MAX_SCORE float64 = 10.0

type score struct {
	category string
	feature  string
	descr    string
	score    float64
	ignore   bool
}

func newScoreFromCheck(c *check) *score {
	return &score{
		category: c.Category,
		feature:  c.Key,
		ignore:   false,
	}
}

func (s *score) setScore(f float64) {
	if math.IsNaN(f) {
		s.score = 0.0
	} else {
		s.score = f
	}
}

func (s *score) setDesc(d string) {
	s.descr = d
}

func (s *score) setIgnore(i bool) {
	s.ignore = i
}

func (s score) Category() string {
	return s.category
}

func (s score) Feature() string {
	return s.feature
}

func (s score) Score() float64 {
	return s.score
}

func (s score) Ignore() bool {
	return s.ignore
}

func (s score) Descr() string {
	return s.descr
}

func (s score) MaxScore() float64 {
	return MAX_SCORE
}
