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

package v2

// FeatureScore is returned by a feature function.
type FeatureScore struct {
	Score  float64 // 0..10
	Desc   string  // e.g. "235/247 have versions"
	Ignore bool    // true => exclude from category calc (N/A)
}

// Per-feature result
type FeatureResult struct {
	Key     string
	Weight  float64 // feature weight
	Score   float64
	Desc    string
	Ignored bool
}

// Per-category result
type CategoryResult struct {
	Name     string
	Weight   float64 // category weight
	Score    float64
	Features []FeatureResult
}

// Final result for a SBOM.
type ScoreResult struct {
	Overall    float64
	Categories []CategoryResult
}
