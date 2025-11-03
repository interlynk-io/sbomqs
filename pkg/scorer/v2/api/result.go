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

// Result represents evaluation result of an SBOM
type Result struct {
	Doc            sbom.Document
	Meta           SBOMMeta
	InterlynkScore float64
	Grade          string

	Comprehensive *ComprehensiveResult
	Profiles      *ProfilesResult
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
	CatResult []CategoryResult
}

type ProfilesResult struct {
	ProfResult []ProfileResult
}

func NewProfResults() ProfilesResult {
	return ProfilesResult{}
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
	Name    string
	Key     string
	Weight  float64 // feature weight
	Score   float64
	Desc    string
	Ignored bool
}

type ProfileResult struct {
	Name       string
	Key        string
	Score      float64
	Compliance catalog.ProfComplianceState
	Message    string
	Items      []ProfileFeatureResult
}

func NewProfileResult(profile catalog.ProfSpec) ProfileResult {
	return ProfileResult{
		Name:    profile.Name,
		Message: profile.Description,
		Key:     string(profile.Key),
		Score:   0.0,
		Items:   make([]ProfileFeatureResult, 0, len(profile.Features)),
		// Compliance: ProfileFail,
	}
}

type ProfileFeatureResult struct {
	Name     string
	Key      string
	Required bool
	Score    float64
	Passed   bool
	Desc     string
}

func NewProfFeatResult(pFeat catalog.ProfFeatSpec) ProfileFeatureResult {
	return ProfileFeatureResult{
		Name:     pFeat.Name,
		Key:      string(pFeat.Key),
		Required: pFeat.Required,
		Score:    0.0,
		Passed:   false,
		Desc:     "no evaluator bound",
	}
}

func NewComprFeatResult(comprFeat catalog.ComprFeatSpec) FeatureResult {
	return FeatureResult{
		Name:   comprFeat.Name,
		Key:    string(comprFeat.Key),
		Score:  0.0,
		Weight: comprFeat.Weight,
	}
}

func NewComprResult() ComprehensiveResult {
	return ComprehensiveResult{}
}

func NewCategoryResultFromSpec(cat catalog.ComprCatSpec) CategoryResult {
	return CategoryResult{
		Name:   cat.Name,
		Weight: cat.Weight,
	}
}

func NewResult(doc sbom.Document) *Result {
	return &Result{
		Meta: NewSBOMMeta(doc),
		Doc:  doc,
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
