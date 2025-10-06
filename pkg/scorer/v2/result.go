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

func NewFeatureResultFromSpec(feat FeatureSpec) *FeatureResult {
	return &FeatureResult{
		Key:    feat.Key,
		Weight: feat.Weight,
	}
}

// Per-category result
type CategoryResult struct {
	Name     string
	Weight   float64 // category weight
	Score    float64
	Features []FeatureResult
}

func NewCategoryResultFromSpec(cat CategorySpec) CategoryResult {
	return CategoryResult{
		Name:   cat.Name,
		Weight: cat.Weight,
	}
}

// Final result for a SBOM.
type ScoreResult struct {
	Overall    float64
	Categories []CategoryResult
}

// Result represents result of an SBOM
type Result struct {
	Spec           string
	SpecVersion    string
	FileFormat     string
	Filename       string
	NumComponents  int
	CreationTime   string
	InterlynkScore float64
	Grade          string
	Categories     []CategoryResult
}

func NewResult(doc sbom.Document) *Result {
	return &Result{
		NumComponents: len(doc.Components()),
		CreationTime:  doc.Spec().GetCreationTimestamp(),
		Spec:          doc.Spec().GetName(),
		SpecVersion:   doc.Spec().GetVersion(),
		FileFormat:    doc.Spec().FileFormat(),
	}
}
