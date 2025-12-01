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
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
)

// Result represents the complete evaluation outcome for an SBOM document.
// It contains the original SBOM document, metadata, and scoring results from
// either comprehensive analysis, profile-based analysis, or both. This is the
// primary return type for all SBOM scoring operations.
type Result struct {
	Doc  sbom.Document
	Meta SBOMMeta
	// InterlynkScore float64
	// Grade          string

	Comprehensive *ComprehensiveResult
	Profiles      *ProfilesResult
}

// SBOMMeta represents common metadata extracted from an SBOM document.
// It provides essential information about the SBOM specification, format,
// and basic structural characteristics used for reporting and analysis.
type SBOMMeta struct {
	Spec          string
	SpecVersion   string
	FileFormat    string
	Filename      string
	NumComponents int
	CreationTime  string
}

// ComprehensiveResult represents the outcome of comprehensive SBOM scoring.
// This analysis evaluates an SBOM across multiple categories with weighted
// scoring to produce an overall quality assessment and grade.
type ComprehensiveResult struct {
	InterlynkScore float64
	Grade          string
	CatResult      []CategoryResult
}

// ProfilesResult represents the outcome of profile-based SBOM evaluation.
// It contains results from evaluating an SBOM against one or more compliance
// profiles, each with specific requirements and scoring criteria.
type ProfilesResult struct {
	ProfResult []ProfileResult
}

// NewProfResults creates a new ProfilesResult with an empty slice of profile results.
// This constructor initializes the structure for collecting profile evaluation outcomes.
func NewProfResults() ProfilesResult {
	return ProfilesResult{}
}

// CategoryResult represents the evaluation outcome for a single scoring category.
// In comprehensive scoring, categories group related features and are weighted
// to contribute to the overall SBOM quality score. Examples include categories
// like "Structural", "Semantic", or "Quality".
type CategoryResult struct {
	Key      string
	Name     string
	Weight   float64 // category weight
	Score    float64
	Features []FeatureResult
}

// FeatureResult represents the evaluation outcome for a single scoring feature.
// Features are specific SBOM characteristics that are evaluated within categories,
// such as "component names present" or "dependency relationships defined".
// Each feature contributes to its parent category's score based on its weight.
type FeatureResult struct {
	Name    string
	Key     string
	Weight  float64 // feature weight
	Score   float64
	Desc    string
	Ignored bool
}

// ProfileResult represents the evaluation outcome for a single compliance profile.
// Profiles define specific requirements for SBOM compliance (e.g., NTIA, BSI, OpenChain).
// Each profile has required and optional features that determine compliance status.
type ProfileResult struct {
	Name           string
	Key            string
	Score          float64
	Compliance     catalog.ProfComplianceState
	Message        string
	Items          []ProfileFeatureResult
	Grade          string
	InterlynkScore float64
}

// NewProfileResult creates a new ProfileResult from a profile specification.
// It initializes the result structure with profile metadata and prepares
// space for feature evaluation results.
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

// ProfileFeatureResult represents the evaluation outcome for a single feature within a profile.
// Profile features define specific requirements that an SBOM must meet to comply
// with a particular profile. Features can be required (must pass) or optional
// (contribute to overall score but don't affect compliance).
type ProfileFeatureResult struct {
	Name     string
	Key      string
	Required bool
	Score    float64
	Passed   bool
	Desc     string
}

// NewProfFeatResult creates a new ProfileFeatureResult from a profile feature specification.
// It initializes the result structure with feature metadata and default values
// for evaluation outcomes.
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

// NewComprFeatResult creates a new FeatureResult from a comprehensive feature specification.
// It initializes the result structure for comprehensive scoring with feature
// metadata and weight information.
func NewComprFeatResult(comprFeat catalog.ComprFeatSpec) FeatureResult {
	return FeatureResult{
		Name:   comprFeat.Name,
		Key:    string(comprFeat.Key),
		Score:  0.0,
		Weight: comprFeat.Weight,
	}
}

// NewComprResult creates a new ComprehensiveResult with zero values.
// This constructor initializes the structure for collecting comprehensive
// scoring outcomes across categories and features.
func NewComprResult() ComprehensiveResult {
	return ComprehensiveResult{}
}

// NewCategoryResultFromSpec creates a new CategoryResult from a comprehensive category specification.
// It initializes the result structure with category metadata including name,
// key, and weight for comprehensive scoring.
func NewCategoryResultFromSpec(cat catalog.ComprCatSpec) CategoryResult {
	return CategoryResult{
		Key:    cat.Key,
		Name:   cat.Name,
		Weight: cat.Weight,
	}
}

// NewResult creates a new Result structure from an SBOM document.
// It initializes the result with document metadata and prepares it for
// receiving scoring outcomes from comprehensive or profile-based evaluation.
func NewResult(doc sbom.Document) *Result {
	return &Result{
		Meta: NewSBOMMeta(doc),
		Doc:  doc,
	}
}

// NewSBOMMeta creates a new SBOMMeta structure by extracting metadata from an SBOM document.
// It populates common metadata fields like specification type, version, format,
// and structural information such as component count and creation timestamp.
func NewSBOMMeta(doc sbom.Document) SBOMMeta {
	return SBOMMeta{
		NumComponents: len(doc.Components()),
		CreationTime:  doc.Spec().GetCreationTimestamp(),
		Spec:          doc.Spec().GetSpecType(),
		SpecVersion:   doc.Spec().GetVersion(),
		FileFormat:    doc.Spec().FileFormat(),
	}
}
