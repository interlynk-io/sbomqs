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

package config

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// // Common file-level metadata
// type SBOMMeta struct {
// 	Spec          string
// 	SpecVersion   string
// 	FileFormat    string
// 	Filename      string
// 	NumComponents int
// 	CreationTime  string
// }

// // Result represents result of an SBOM
// type Result struct {
// 	Meta SBOMMeta

// 	Comprehensive *ComprehensiveResult
// 	Profiles      []profiles.ProfileResult
// }

// // Comprehensive (quality) scoring
// type ComprehensiveResult struct {
// 	InterlynkScore float64
// 	Grade          string
// 	Categories     []CategoryResult
// }

// // Category result
// type CategoryResult struct {
// 	Name     string
// 	Weight   float64 // category weight
// 	Score    float64
// 	Features []FeatureResult
// }

// // CategorySpec represent properties of a category.
// type CategorySpec struct {
// 	Name     string
// 	Weight   float64
// 	Features []FeatureSpec
// }

// // FeatureSpec represents properties of a feature.
// type FeatureSpec struct {
// 	Key      string
// 	Weight   float64
// 	Evaluate FeatureFunc
// }

// // feature function is a corresponding funtion for a feature.
// type FeatureFunc func(doc sbom.Document) FeatureScore

// // FeatureScore is returned by a feature function.
// type FeatureScore struct {
// 	Score  float64
// 	Desc   string // e.g. "235/247 have versions"
// 	Ignore bool
// }

// func NewCategoryResultFromSpec(cat CategorySpec) CategoryResult {
// 	return CategoryResult{
// 		Name:   cat.Name,
// 		Weight: cat.Weight,
// 	}
// }

// func NewResult(doc sbom.Document) *Result {
// 	return &Result{
// 		Meta: NewSBOMMeta(doc),
// 	}
// }

// func NewSBOMMeta(doc sbom.Document) SBOMMeta {
// 	return SBOMMeta{
// 		NumComponents: len(doc.Components()),
// 		CreationTime:  doc.Spec().GetCreationTimestamp(),
// 		Spec:          doc.Spec().GetName(),
// 		SpecVersion:   doc.Spec().GetVersion(),
// 		FileFormat:    doc.Spec().FileFormat(),
// 	}
// }

type Config struct {
	// Categories to score (e.g., "provenance", "completeness")
	Categories []string

	// Features to score (e.g., "components", "dependencies")
	Features []string

	// Optional path to a config file for filters
	ConfigFile string

	// profiles
	Profile []string

	SignatureBundle sbom.Signature
}
