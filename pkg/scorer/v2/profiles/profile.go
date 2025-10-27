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
	"fmt"
	"strings"

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

// Evaluates one SBOM against one or more profile names (aliases allowed).
// Never panics, never early-returns the whole SBOM; collects per-profile errors.
func Evaluate(ctx context.Context, catal *catalog.Catalog, profileKeys []catalog.ProfileKey, doc sbom.Document) ([]api.ProfileResult, []error) {
	var results []api.ProfileResult
	var errs []error

	// selectedProfiles, errs := filterProfiles(profileNames)
	// if errs != nil {
	// 	return nil, errs
	// }

	allProfiles := make([]catalog.ProfSpec, 0, len(profileKeys))

	for _, pKey := range profileKeys {
		pSpec, ok := catal.Profiles[pKey]
		if ok {
			allProfiles = append(allProfiles, pSpec)
		}
	}

	for _, profile := range allProfiles {
		res := evaluateEachProfile(ctx, doc, profile)
		results = append(results, res)
	}

	return results, errs
}

func filterProfiles(profileNames []string) ([]catalog.ProfSpec, []error) {
	var errs []error

	seen := make(map[string]struct{}, len(profileNames))
	filterProfiles := make([]catalog.ProfSpec, 0, len(profileNames))

	for i, profile := range profileNames {

		name := strings.TrimSpace(strings.ToLower(profile))
		if name == "" {
			errs = append(errs, fmt.Errorf("profiles: empty profile name at position %d", i))
			continue
		}

		if _, dup := seen[name]; dup {
			errs = append(errs, fmt.Errorf("profiles: duplicate requested profile %q", profile))
			continue
		}

		spec, ok := profileToSpec[name]
		if !ok {
			errs = append(errs, fmt.Errorf("profiles: unknown profile %q (available: %s)", profile))
			continue
		}
		filterProfiles = append(filterProfiles, spec)
	}

	return filterProfiles, errs
}

func evaluateEachProfile(ctx context.Context, doc sbom.Document, profile catalog.ProfSpec) api.ProfileResult {
	result := api.NewProfileResult(profile)
	var countNonNA int
	var sumScore float64

	for _, pFeat := range profile.Features {
		featResult := api.NewProfileFeatureResult(pFeat)

		// result.Items = append(result.Items, featResult)
		s := pFeat.Evaluate(doc)

		if s.Ignore {
			featResult.Passed = !pFeat.Required
		} else if pFeat.Required {
			featResult.Passed = (s.Score >= 10.0)
		} else {
			featResult.Passed = (s.Score > 0.0)
		}

		featResult.Score = s.Score
		featResult.Desc = s.Desc

		result.Items = append(result.Items, featResult)

		if !s.Ignore {
			sumScore += s.Score
			countNonNA++
		}
	}

	if countNonNA > 0 {
		result.Score = sumScore / float64(countNonNA)
	}

	return result
}
