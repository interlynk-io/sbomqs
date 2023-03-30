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

package scorerv2

type Score struct {
	Score  float64 `json:"score"`
	Ignore bool    `json:"ignore"`
	Check  *Check
}

type Check struct {
	Name      string  `json:"name"`
	ConfigKey string  `json:"key,omitempty"`
	Weight    float64 `json:"weight,omitempty"`
	Enabled   bool    `json:"enabled,omitempty"`

	PreC func(sbom.Document) bool  `json:"-"`
	Run  func(sbom.Document) Score `json:"-"`
}

type CheckCategory struct {
	Name      string  `json:"name"`
	Weight    float64 `json:"weight,omitempty"`
	Enabled   bool    `json:"enabled,omitempty"`
	ConfigKey string  `json:"key,omitempty"`

	Rules []Rule `json:"rules,omitempty"`
}

type CheckSet struct {
	Name    string         `json:"name"`
	Enabled bool           `json:"enabled,omitempty"`
	Cats    []RuleCategory `json:"categories,omitempty"`
}
