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

package catalog

import "github.com/interlynk-io/sbomqs/v2/pkg/sbom"

// ComprFeatSpec represents a feature specification for comprehensive scoring.
// Features define specific SBOM characteristics to be evaluated, such as
// "components have names" or "dependencies are defined". Each feature has
// a weight and an evaluation function.
type ComprFeatSpec struct {
	Name        string
	Description string
	Ignore      bool
	Key         string
	Weight      float64
	Evaluate    ComprFeatEval
}

// ComprFeatEval represents an evaluation function for a comprehensive feature.
// It takes an SBOM document and returns a score with descriptive information
// about the evaluation outcome.
type ComprFeatEval func(doc sbom.Document) ComprFeatScore

// ComprFeatScore represents the evaluation result for a comprehensive feature.
// It contains the numeric score, a human-readable description of the outcome,
// and whether the feature should be ignored in scoring calculations.
type ComprFeatScore struct {
	Score  float64
	Desc   string // e.g. "235/247 have versions"
	Ignore bool
}
