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

package scvs

type ScvsScore interface {
	Feature() string
	L1Score() string
	L2Score() string
	L3Score() string
	Description() string
}

type scvsScore struct {
	feature     string
	l1Score     string
	l2Score     string
	l3Score     string
	description string
}

func newScoreFromScvsCheck(c *scvsCheck) *scvsScore {
	return &scvsScore{
		feature: c.Key,
	}
}

func (s *scvsScore) setL3Score(v string) {
	s.l3Score = v
}

func (s *scvsScore) setL2Score(v string) {
	s.l2Score = v
}

func (s *scvsScore) setL1Score(v string) {
	s.l1Score = v
}

func (s scvsScore) Feature() string {
	return s.feature
}

func (s scvsScore) L3Score() string {
	return s.l3Score
}

func (s scvsScore) L1Score() string {
	return s.l1Score
}

func (s scvsScore) L2Score() string {
	return s.l2Score
}

func (s scvsScore) Description() string {
	return s.description
}
