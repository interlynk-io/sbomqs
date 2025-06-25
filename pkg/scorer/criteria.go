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

package scorer

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

type category string

const (
	structural category = "Structural"
	ntiam      category = "NTIA-minimum-elements"
	semantic   category = "Semantic"
	quality    category = "Quality"
	sharing    category = "Sharing"
	bsiv1_1    category = "bsi-v1.1"
	bsiv2_0    category = "bsi-v2.0"
)

type check struct {
	Category string `yaml:"category"`
	Key      string `yaml:"feature"`
	Ignore   bool   `yaml:"disabled"`
	Descr    string `yaml:"descrption"`
	evaluate func(sbom.Document, *check) score
}

var checks = []check{
	// ntia minimum
	{string(ntiam), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(ntiam), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(ntiam), "comp_with_uniq_ids", false, "components have uniq ids", compWithUniqIDCheck},
	{string(ntiam), "comp_with_supplier", false, "components have suppliers", compWithSupplierCheck},
	{string(ntiam), "sbom_creation_timestamp", false, "sbom has creation timestamp", sbomWithTimeStampCheck},
	{string(ntiam), "sbom_authors", false, "sbom has authors", sbomWithAuthorsCheck},
	{string(ntiam), "sbom_dependencies", false, "primary comp has dependencies", sbomWithDepedenciesCheck},

	// bsi-v1.1
	{string(bsiv1_1), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(bsiv1_1), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(bsiv1_1), "comp_with_uniq_ids", false, "components have uniq ids", bsiCompWithUniqIDCheck},
	{string(bsiv1_1), "comp_with_supplier", false, "components have suppliers", compWithSupplierCheck},
	{string(bsiv1_1), "comp_with_licenses", false, "components have licenses", compWithLicensesCompliantCheck},
	{string(bsiv1_1), "comp_with_checksums_sha256", false, "components have checksums with sha256", compWithSHA256ChecksumsCheck},
	{string(bsiv1_1), "comp_with_source_code_uri", false, "components have source code URI", compWithSourceCodeURICheck},
	{string(bsiv1_1), "comp_with_source_code_hash", false, "components have source code hash", compWithSourceCodeHashCheck},
	{string(bsiv1_1), "comp_with_executable_uri", false, "components have executable URI", compWithExecutableURICheck},
	{string(bsiv1_1), "comp_with_dependencies", false, "components have dependencies", compWithDependencyCheck},
	{string(bsiv1_1), "spec_with_version_compliant", false, "SBOM Specification", specWithVersionCompliant},
	{string(bsiv1_1), "sbom_creation_timestamp", false, "sbom has creation timestamp", sbomWithTimeStampCheck},
	{string(bsiv1_1), "sbom_authors", false, "sbom has authors", sbomWithAuthorsCheck},
	{string(bsiv1_1), "sbom_dependencies", false, "sbom has dependencies", sbomWithDepedenciesCheck},
	{string(bsiv1_1), "sbom_with_uri", false, "sbom has URI", sbomWithURICheck},

	// bsi-v2.0.0
	{string(bsiv2_0), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(bsiv2_0), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(bsiv2_0), "comp_with_uniq_ids", false, "components have uniq ids", bsiCompWithUniqIDCheck},
	{string(bsiv2_0), "comp_with_supplier", false, "components have suppliers", compWithSupplierCheck},
	{string(bsiv2_0), "comp_with_associated_license", false, "components have associated licenses", compWithAssociatedLicensesCheck},
	{string(bsiv2_0), "comp_with_concluded_license", false, "components have concluded licenses", compWithConcludedLicensesCheck},
	{string(bsiv2_0), "comp_with_declared_license", false, "components have declared licenses", compWithDeclaredLicensesCheck},
	{string(bsiv2_0), "comp_with_source_code_uri", false, "components have source code URI", compWithSourceCodeURICheck},
	{string(bsiv2_0), "comp_with_source_code_hash", false, "components have source code hash", compWithSourceCodeHashCheck},
	{string(bsiv2_0), "comp_with_executable_uri", false, "components have executable URI", compWithExecutableURICheck},
	{string(bsiv2_0), "comp_with_executable_hash", false, "components have executable checksums", compWithSHA256ChecksumsCheck},
	{string(bsiv2_0), "comp_with_dependencies", false, "components have dependencies", compWithDependencyCheck},
	{string(bsiv2_0), "spec_with_version_compliant", false, "SBOM Specification", specWithVersionCompliant},
	{string(bsiv2_0), "sbom_creation_timestamp", false, "sbom has creation timestamp", sbomWithTimeStampCheck},
	{string(bsiv2_0), "sbom_authors", false, "sbom has authors", sbomWithAuthorsCheck},
	{string(bsiv2_0), "sbom_build_process", false, "SBOM build process", sbomBuildLifecycleCheck},
	{string(bsiv2_0), "sbom_with_uri", false, "sbom has URI", sbomWithURICheck},
	{string(bsiv2_0), "sbom_dependencies", false, "primary comp has dependencies", sbomWithDepedenciesCheck},
	{string(bsiv2_0), "sbom_with_vuln", false, "SBOM has vulnerability", sbomWithVulnCheck},
	{string(bsiv2_0), "sbom_with_signature", false, "sbom has signature", sbomWithSignatureCheck},

	// semantic
	{string(semantic), "sbom_required_fields", false, "sbom has all required fields", sbomWithRequiredFieldCheck},
	{string(semantic), "comp_with_licenses", false, "components have licenses", compWithLicensesCheck},
	{string(semantic), "comp_with_checksums", false, "components have checksums", compWithChecksumsCheck},

	// quality
	{string(quality), "comp_valid_licenses", false, "components with valid licenses", compWithValidLicensesCheck},
	{string(quality), "comp_with_primary_purpose", false, "components with primary purpose", compWithPrimaryPackageCheck},
	{string(quality), "comp_with_deprecated_licenses", false, "components with deprecated licenses", compWithNoDepLicensesCheck},
	{string(quality), "comp_with_restrictive_licenses", false, "components with restrictive_licenses", compWithRestrictedLicensesCheck},
	{string(quality), "comp_with_any_vuln_lookup_id", false, "components with any vulnerability lookup id", compWithAnyLookupIDCheck},
	{string(quality), "comp_with_multi_vuln_lookup_id", false, "components with multiple vulnerability lookup id", compWithMultipleIDCheck},
	{string(quality), "sbom_with_creator_and_version", false, "sbom has creator and version", sbomWithCreatorCheck},
	{string(quality), "sbom_with_primary_component", false, "sbom has primary component", sbomWithPrimaryComponentCheck},

	// sharing
	{string(sharing), "sbom_sharable", false, "sbom document has a sharable license", sharableLicenseCheck},

	// structural
	{string(structural), "sbom_spec", false, "SBOM Specification", specCheck},
	{string(structural), "sbom_spec_version", false, "Spec Version", specVersionCheck},
	{string(structural), "sbom_file_format", false, "SBOM File Format", sbomFileFormatCheck},
	{string(structural), "sbom_parsable", false, "Spec is parsable", specParsableCheck},
}
