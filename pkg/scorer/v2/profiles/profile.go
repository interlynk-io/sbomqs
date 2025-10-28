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

package profiles

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

// type ProfileResult struct {
// 	Name       string
// 	Score      float64
// 	Compliance ProfileComplianceState
// 	Message    string
// 	Items      []ProfileFeatureResult
// }

// func NewProfileResult(profile ProfileSpec) ProfileResult {
// 	return ProfileResult{
// 		Name:       profile.Name,
// 		Score:      0.0,
// 		Items:      make([]ProfileFeatureResult, 0, len(profile.Features)),
// 		Compliance: ProfileFail,
// 	}
// }

// type ProfileFeatureResult struct {
// 	Key      string
// 	Required bool
// 	Score    float64
// 	Passed   bool
// 	Desc     string
// }

// func NewProfileFeatureResult(f ProfileFeatureSpec) ProfileFeatureResult {
// 	return ProfileFeatureResult{
// 		Key:      f.Name,
// 		Required: f.Required,
// 		Score:    0.0,
// 		Passed:   false,
// 		Desc:     "no evaluator bound",
// 	}
// }

// // ProfileSpec ofile is one compliance profile (e.g., ntia, bsi-v2.0, oct).
// type ProfileSpec struct {
// 	Name        string
// 	Description string
// 	Features    []ProfileFeatureSpec
// }

// type ProfileFeatureSpec struct {
// 	Name        string
// 	Required    bool
// 	Description string
// 	Evaluate    ProfileFeatureFunc
// }

// type ProfileFeatureFunc func(doc sbom.Document) ProfileFeatureScore

// type ProfileFeatureScore struct {
// 	Score  float64
// 	Desc   string
// 	Ignore bool
// }

// type ProfileComplianceState string

// const (
// 	ProfilePass    catalog.ProfileComplianceState = "PASS"
// 	ProfileFail    catalog.ProfileComplianceState = "FAIL"
// 	ProfileSkipped catalog.ProfileComplianceState = "SKIPPED" // e.g., profile not applicable (OCT on CDX)
// 	ProfileError   catalog.ProfileComplianceState = "ERROR"   // evaluation failed (unexpected)
// )

// var profileToSpec = map[string]catalog.ProfileSpec{
// 	"ntia":     NTIAProfile,
// 	"bsi-v1.1": BSIV11Profile,
// 	"bsi-v2.0": BSIV20Profile,
// 	"oct":      OCTProfile,
// }

// func BaseProfiles() []catalog.ProfileSpec {
// 	return []catalog.ProfileSpec{
// 		NTIAProfile,
// 		BSIV11Profile,
// 		BSIV20Profile,
// 		OCTProfile,
// 	}
// }

// var NTIAProfile = catalog.ProfileSpec{
// 	Name: "NTIA-minimum-elements",
// 	Features: []catalog.ProfileFeatureSpec{
// 		{Name: "sbom_with_spec", Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_spec_version", Required: true, Description: "Supported spec version declared", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_file_format", Required: true, Description: "Supported file format", Evaluate: nil},
// 		{Name: "comp_with_name", Required: true, Description: "All components have names", Evaluate: compWithNameCheck},
// 		{Name: "comp_with_version", Required: true, Description: "Components have versions", Evaluate: compWithVersionCheck},
// 		{Name: "comp_with_identifiers", Required: true, Description: "Unique local identifiers (SPDXID / bom-ref)", Evaluate: compWithUniqIDCheck},
// 		{Name: "comp_with_supplier", Required: true, Description: "Supplier/manufacturer info", Evaluate: compWithSupplierCheck},
// 		{Name: "comp_with_dependencies", Required: true, Description: "Dependency mapping present", Evaluate: nil},
// 		{Name: "sbom_creation_timestamp", Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: sbomWithTimeStampCheck},
// 		{Name: "sbom_authors", Required: true, Description: "Author/creator info", Evaluate: sbomWithAuthorsCheck},
// 	},
// }

// var BSIV11Profile = catalog.ProfileSpec{
// 	Name: "BSI-V1.1",
// 	Features: []catalog.ProfileFeatureSpec{
// 		{Name: "sbom_with_spec", Required: true, Description: "SPDX or CycloneDX", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_spec_version", Required: true, Description: "Supported spec version", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_file_format", Required: true, Description: "Supported file format", Evaluate: nil},
// 		{Name: "sbom_creation_timestamp", Required: true, Description: "Creation timestamp", Evaluate: sbomWithTimeStampCheck},
// 		{Name: "sbom_authors", Required: true, Description: "Creator info", Evaluate: sbomWithAuthorsCheck},
// 		{Name: "sbom_namespace", Required: true, Description: "Unique SBOM identifier", Evaluate: sbomWithURICheck},
// 		{Name: "comp_with_name", Required: true, Description: "Names present", Evaluate: compWithNameCheck},
// 		{Name: "comp_with_version", Required: true, Description: "Versions present", Evaluate: compWithVersionCheck},
// 		{Name: "comp_with_licenses", Required: true, Description: "License info", Evaluate: compWithLicensesCheck},
// 		{Name: "comp_with_checksums", Required: true, Description: "Checksums present", Evaluate: octCompWithSHA256Check},
// 		{Name: "comp_with_dependencies", Required: true, Description: "Dependencies present", Evaluate: compWithDependencyCheck},
// 		{Name: "comp_with_source_code", Required: false, Description: "Source/VCS references", Evaluate: compWithSourceCodeURICheck},
// 		{Name: "comp_with_supplier", Required: true, Description: "Supplier info", Evaluate: compWithSupplierCheck},
// 	},
// }

// var BSIV20Profile = catalog.ProfileSpec{
// 	Name: "BSI-V2.0",
// 	Features: []catalog.ProfileFeatureSpec{
// 		{Name: "sbom_with_spec", Required: true, Description: "SPDX or CycloneDX", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_spec_version", Required: true, Description: "Supported spec version", Evaluate: sbomWithVersionCompliant},
// 		{Name: "sbom_file_format", Required: true, Description: "Supported file format", Evaluate: nil},
// 		{Name: "sbom_schema_valid", Required: true, Description: "Schema validation", Evaluate: sbomWithVersionCompliant},
// 		{Name: "comp_with_checksums", Required: true, Description: "Checksums", Evaluate: compWithSHA256ChecksumsCheck},
// 		{Name: "comp_with_sha256", Required: true, Description: "SHA-256 or stronger", Evaluate: compWithSHA256ChecksumsCheck},
// 		{Name: "sbom_signature", Required: true, Description: "Digital signature", Evaluate: sbomWithSignatureCheck},
// 		{Name: "comp_with_valid_licenses", Required: true, Description: "Valid SPDX license IDs", Evaluate: compWithLicensesCompliantCheck},
// 		{Name: "sbom_data_license", Required: true, Description: "Data license", Evaluate: nil},
// 		{Name: "comp_with_name", Required: true, Description: "Names present", Evaluate: compWithNameCheck},
// 		{Name: "comp_with_version", Required: true, Description: "Versions present", Evaluate: compWithVersionCheck},
// 		{Name: "comp_with_identifiers", Required: true, Description: "Local identifiers", Evaluate: compWithUniqIDCheck},
// 		{Name: "comp_with_supplier", Required: true, Description: "Supplier info", Evaluate: compWithSupplierCheck},
// 		{Name: "comp_with_dependencies", Required: true, Description: "Dependencies present", Evaluate: compWithDependencyCheck},
// 		{Name: "comp_with_purl", Required: false, Description: "PURLs", Evaluate: compWithUniqIDCheck},
// 		{Name: "comp_with_cpe", Required: false, Description: "CPEs", Evaluate: nil},
// 	},
// }

// var OCTProfile = catalog.ProfileSpec{
// 	Name: "OpenChain Telco",
// 	Features: []catalog.ProfileFeatureSpec{
// 		// SPDX doc essentials
// 		{Name: "sbom_with_spec", Required: true, Description: "SPDX declared", Evaluate: octSBOMSpec},
// 		{Name: "sbom_spec_version", Required: true, Description: "Supported SPDX version", Evaluate: octSBOMSpecVersionCheck},
// 		{Name: "sbom_namespace", Required: true, Description: "SPDX namespace", Evaluate: octSBOMNamespaceCheck},
// 		{Name: "sbom_data_license", Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: octSBOMDataLicenseCheck},
// 		{Name: "sbom_tool_version", Required: true, Description: "Creator tool + version", Evaluate: octSBOMToolCreationCheck},
// 		// Packages
// 		{Name: "comp_with_name", Required: true, Description: "Package names", Evaluate: octCompWithNameCheck},
// 		{Name: "comp_with_version", Required: true, Description: "Package versions", Evaluate: octCompWithVersionCheck},
// 		{Name: "comp_with_identifiers", Required: true, Description: "Package SPDXIDs", Evaluate: octCompWithSpdxIDCheck},
// 		{Name: "comp_with_licenses", Required: true, Description: "Concluded license", Evaluate: octCompWithConcludedLicenseCheck},
// 		{Name: "comp_with_declared_licenses", Required: true, Description: "Declared/original license", Evaluate: octCompWithDeclaredLicenseCheck},
// 		{Name: "comp_with_checksums", Required: true, Description: "Checksums", Evaluate: octCompWithSHA256Check},
// 		{Name: "comp_with_supplier", Required: true, Description: "Supplier info", Evaluate: octCompWithSupplierCheck},
// 		{Name: "comp_with_source_code", Required: false, Description: "Source/VCS", Evaluate: octCompWithSupplierCheck},
// 		{Name: "comp_with_dependencies", Required: true, Description: "Dependencies", Evaluate: octCompWithExternalRefsCheck},
// 	},
// }

// Evaluate evaluates the profiles against an SBOM and returns their results.
// Unknown profile keys are skipped
// Returns collected profile results
func Evaluate(ctx context.Context, catal *catalog.Catalog, profileKeys []catalog.ProfileKey, doc sbom.Document) []api.ProfileResult {
	var results []api.ProfileResult

	allProfiles := make([]catalog.ProfSpec, 0, len(profileKeys))

	for _, key := range profileKeys {
		profile, ok := catal.Profiles[key]
		if ok {
			allProfiles = append(allProfiles, profile)
		}
	}

	for _, profile := range allProfiles {
		profResult := evaluateEachProfile(ctx, doc, profile, catal)
		results = append(results, profResult)
	}

	return results
}

// evaluateEachProfile runs evaluation for a profile.
// It executes all feature checks defined in the profile,
// collects their results, aggregates the scores, and
// returns a completed ProfileResult (with metadata included).
func evaluateEachProfile(ctx context.Context, doc sbom.Document, profile catalog.ProfSpec, catal *catalog.Catalog) api.ProfileResult {
	var countNonNA int
	var sumScore float64

	proResult := api.NewProfileResult(profile)

	for _, pFeatKey := range profile.Features {

		// extract corresponding profileFeatureSpec to a featureKey
		pFeat, ok := catal.ProfFeatures[catalog.ProfFeatKey(pFeatKey)]
		if !ok {
			continue
		}

		pFeatResult := api.NewProfFeatResult(pFeat)

		// evaluate feature
		pFeatScore := pFeat.Evaluate(doc)

		if pFeatScore.Ignore {
			pFeatResult.Passed = !pFeat.Required
		} else if pFeat.Required {
			pFeatResult.Passed = (pFeatScore.Score >= 10.0)
		} else {
			pFeatResult.Passed = (pFeatScore.Score > 0.0)
		}

		pFeatResult.Score = pFeatScore.Score
		pFeatResult.Desc = pFeatScore.Desc

		proResult.Items = append(proResult.Items, pFeatResult)

		if !pFeatScore.Ignore {
			sumScore += pFeatScore.Score
			countNonNA++
		}
	}

	if countNonNA > 0 {
		proResult.Score = sumScore / float64(countNonNA)
	}

	return proResult
}
