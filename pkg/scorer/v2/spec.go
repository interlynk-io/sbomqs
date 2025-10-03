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

import "github.com/interlynk-io/sbomqs/pkg/sbom"

// A feature function is a valuating funtion for a feature.
// It returns a raw 0..10 score, a description, and whether to ignore (N/A).
type FeatureFunc func(doc sbom.Document) FeatureScore

// FeatureSpec represents properties of a feature.
type FeatureSpec struct {
	Key      string
	Weight   float64
	Evaluate FeatureFunc
}

// CategorySpec represent properties of a category.
type CategorySpec struct {
	Name     string
	Weight   float64
	Features []FeatureSpec
}

type Config struct {
	// Categories to score (e.g., "provenance", "completeness")
	Categories []string

	// Features to score (e.g., "components", "dependencies")
	Features []string

	// Optional path to a config file for filters
	ConfigFile string

	SignatureBundle sbom.Signature
}

// extractMeta pulls the data to show in the final output.
type interlynkMeta struct {
	Filename      string
	NumComponents int
	CreationTime  string
	Spec          string
	SpecVersion   string
	FileFormat    string
}
