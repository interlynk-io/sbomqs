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

// ProfSpec represents the specification for a compliance profile.
// Profiles define specific requirements for SBOM compliance standards
// such as NTIA, BSI v1.1, BSI v2.0, OpenChain Telco, etc. Each profile
// contains features that must be evaluated for compliance determination.
type ProfSpec struct {
	Name        string
	Description string
	Key         ProfileKey
	Features    []ProfFeatSpec
}

// ProfFeatSpec represents a feature specification within a compliance profile.
// Profile features define specific requirements that an SBOM must meet,
// with some features being required (must pass) and others being optional.
type ProfFeatSpec struct {
	Name        string
	Required    bool
	Description string
	Key         string
	Evaluate    ProfFeatEval
}

// ProfFeatEval represents an evaluation function for a profile feature.
// It takes an SBOM document and returns a score with descriptive information
// about whether the feature requirement is satisfied.
type ProfFeatEval func(doc sbom.Document) ProfFeatScore

// ProfFeatScore represents the evaluation result for a profile feature.
// It contains the numeric score, a description of the evaluation outcome,
// and whether the feature should be ignored in compliance calculations.
type ProfFeatScore struct {
	Score  float64
	Desc   string
	Ignore bool
}

// ProfComplianceState represents the compliance status of a profile evaluation.
// It indicates whether an SBOM meets the requirements of a specific compliance profile.
type ProfComplianceState string
