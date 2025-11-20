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

// ProfSpec represents specification of each profiles.
// e.g. ntia, bsi-v1.1, bsi-v2.0, oct, etc
type ProfSpec struct {
	Name        string
	Description string
	Key         ProfileKey
	Features    []ProfFeatSpec
}

// ProfFeatSpec represents specification of feature of each profiles.
type ProfFeatSpec struct {
	Name        string
	Required    bool
	Description string
	Key         string
	Evaluate    ProfFeatEval
}

// ProfFeatEval represents evaluation of corresponding feature.
type ProfFeatEval func(doc sbom.Document) ProfFeatScore

// ProfFeatScore carries score of a profiles feature
type ProfFeatScore struct {
	Score  float64
	Desc   string
	Ignore bool
}

type ProfComplianceState string
