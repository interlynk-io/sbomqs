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

package api

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

// Result represents result of an SBOM
type Result struct {
	Meta SBOMMeta

	Comprehensive *ComprehensiveResult
	Profiles      []ProfileResult
}

// Common file-level metadata
type SBOMMeta struct {
	Spec          string
	SpecVersion   string
	FileFormat    string
	Filename      string
	NumComponents int
	CreationTime  string
}

// Comprehensive (quality) scoring
type ComprehensiveResult struct {
	InterlynkScore float64
	Grade          string
	Categories     []CategoryResult
}

// Category result
type CategoryResult struct {
	Name     string
	Weight   float64 // category weight
	Score    float64
	Features []FeatureResult
}

// feature result
type FeatureResult struct {
	Key     string
	Weight  float64 // feature weight
	Score   float64
	Desc    string
	Ignored bool
}

type ProfileResult struct {
	Name       string
	Score      float64
	Compliance catalog.ProfileComplianceState
	Message    string
	Items      []ProfileFeatureResult
}

func NewProfileResult(profile catalog.ProfileSpec) ProfileResult {
	return ProfileResult{
		Name:       profile.Name,
		Score:      0.0,
		Items:      make([]ProfileFeatureResult, 0, len(profile.Features)),
		Compliance: catalog.ProfileFail,
	}
}

type ProfileFeatureResult struct {
	Key      string
	Required bool
	Score    float64
	Passed   bool
	Desc     string
}

func NewProfileFeatureResult(f ProfileFeatureSpec) ProfileFeatureResult {
	return ProfileFeatureResult{
		Key:      f.Name,
		Required: f.Required,
		Score:    0.0,
		Passed:   false,
		Desc:     "no evaluator bound",
	}
}

func NewCategoryResultFromSpec(cat CategorySpec) CategoryResult {
	return CategoryResult{
		Name:   cat.Name,
		Weight: cat.Weight,
	}
}

func NewResult(doc sbom.Document) *Result {
	return &Result{
		Meta: NewSBOMMeta(doc),
	}
}

func NewSBOMMeta(doc sbom.Document) SBOMMeta {
	return SBOMMeta{
		NumComponents: len(doc.Components()),
		CreationTime:  doc.Spec().GetCreationTimestamp(),
		Spec:          doc.Spec().GetName(),
		SpecVersion:   doc.Spec().GetVersion(),
		FileFormat:    doc.Spec().FileFormat(),
	}
}
