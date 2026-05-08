// Copyright 2026 Interlynk.io
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

import (
	"context"

	"github.com/interlynk-io/sbomqs/v2/pkg/interlynkapi"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// EvalInput bundles all inputs that a comprehensive feature evaluator may need.
// Doc is always present. ComponentQuality is non-nil only when the caller
// successfully fetched results from the Interlynk Component Quality API.
// Passing this explicitly (rather than hiding it in context.Context) makes
// the dependency visible and testable.
type EvalInput struct {
	Doc              sbom.Document
	ComponentQuality *interlynkapi.ComponentQualityResult
}

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

// ComprFeatEval is the evaluation function type for a comprehensive feature.
// ctx carries cancellation and logging; input provides the SBOM document and
// any pre-fetched API data. Most evaluators only use input.Doc; Component
// Quality evaluators additionally use input.ComponentQuality.
type ComprFeatEval func(ctx context.Context, input EvalInput) ComprFeatScore

// ComprFeatScore represents the evaluation result for a comprehensive feature.
// It contains the numeric score, a human-readable description of the outcome,
// and whether the feature should be ignored in scoring calculations.
type ComprFeatScore struct {
	Score  float64
	Desc   string // e.g. "235/247 have versions"
	Ignore bool
}
