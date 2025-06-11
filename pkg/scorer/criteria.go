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
	bsiv1      category = "bsi-v1.1.0"
	bsiv2      category = "bsi-v2.0.0"
)

type check struct {
	Category string `yaml:"category"`
	Key      string `yaml:"feature"`
	Ignore   bool   `yaml:"disabled"`
	Descr    string `yaml:"descrption"`
	evaluate func(sbom.Document, *check) score
}

var checks = []check{
	// structural
	{string(structural), "sbom_spec", false, "SBOM Specification", specCheck},
	{string(structural), "sbom_spec_version", false, "Spec Version", specVersionCheck},
	{string(structural), "sbom_spec_file_format", false, "Spec File Format", specFileFormatCheck},
	{string(structural), "sbom_parsable", false, "Spec is parsable", specParsableCheck},

	// ntia minimum
	{string(ntiam), "comp_with_supplier", false, "components have suppliers", compSupplierCheck},
	{string(ntiam), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(ntiam), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(ntiam), "comp_with_uniq_ids", false, "components have uniq ids", compWithUniqIDCheck},
	{string(ntiam), "sbom_dependencies", false, "sbom has dependencies", docWithDepedenciesCheck},
	{string(ntiam), "sbom_authors", false, "sbom has authors", docWithAuthorsCheck},
	{string(ntiam), "sbom_creation_timestamp", false, "sbom has creation timestamp", docWithTimeStampCheck},

	// bsi-v1
	{string(bsiv1), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(bsiv1), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(bsiv1), "comp_with_uniq_ids", false, "components have uniq ids", bsiCompWithUniqIDCheck},
	{string(bsiv1), "comp_with_supplier", false, "components have suppliers", compSupplierCheck},
	{string(bsiv1), "comp_with_licenses", false, "components have licenses", bsiCompWithLicensesCheck},
	{string(bsiv1), "comp_with_checksums", false, "components have checksums", bsiCompWithChecksumsCheck},
	{string(bsiv1), "comp_with_source_code_uri", false, "components have source code URI", compWithSourceCodeURICheck},
	{string(bsiv1), "comp_with_source_code_hash", false, "components have source code hash", compWithSourceCodeHashCheck},
	{string(bsiv1), "comp_with_executable_uri", false, "components have executable URI", compWithExecutableURICheck},
	{string(bsiv1), "spec_compliant", false, "SBOM Specification", bsiSpecCheck},
	{string(bsiv1), "sbom_authors", false, "sbom has authors", docWithAuthorsCheck},
	{string(bsiv1), "sbom_creation_timestamp", false, "sbom has creation timestamp", docWithTimeStampCheck},
	{string(bsiv1), "sbom_dependencies", false, "sbom has dependencies", docWithDepedenciesCheck},
	{string(bsiv1), "sbom_with_uri", false, "sbom has URI", docWithURICheck},

	// bsi-v1
	{string(bsiv2), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(bsiv2), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(bsiv2), "comp_with_uniq_ids", false, "components have uniq ids", bsiCompWithUniqIDCheck},
	{string(bsiv2), "comp_with_supplier", false, "components have suppliers", compSupplierCheck},

	{string(bsiv2), "comp_with_associated_license", false, "components have associated licenses", bsiCompWithAssociatedLicensesCheck},
	{string(bsiv2), "comp_with_concluded_license", false, "components have concluded licenses", bsiCompWithConcludedLicensesCheck},
	{string(bsiv2), "comp_with_declared_license", false, "components have declared licenses", bsiCompWithDeclaredLicensesCheck},
	// {string(bsiv2), "comp_with_dependencies", false, "components have dependencies", bsiCompWithDependencyCheck},

	{string(bsiv2), "comp_with_source_code_uri", false, "components have source code URI", compWithSourceCodeURICheck},
	{string(bsiv2), "comp_with_source_code_hash", false, "components have source code hash", compWithSourceCodeHashCheck},
	{string(bsiv2), "comp_with_executable_uri", false, "components have executable URI", compWithExecutableURICheck},
	{string(bsiv2), "comp_with_executable_hash", false, "components have executable checksums", bsiCompWithChecksumsCheck},

	{string(bsiv2), "sbom_with_vuln", false, "SBOM has vulnerability", bsiVulnCheck},
	{string(bsiv2), "spec_compliant", false, "SBOM Specification", bsiSpecCheck},
	{string(bsiv2), "sbom_build_process", false, "SBOM build process", docBuildPhaseCheck},
	{string(bsiv2), "sbom_authors", false, "sbom has authors", docWithAuthorsCheck},
	{string(bsiv2), "sbom_creation_timestamp", false, "sbom has creation timestamp", docWithTimeStampCheck},
	{string(bsiv2), "sbom_dependencies", false, "primary comp has dependencies", docWithDepedenciesCheck},
	{string(bsiv2), "sbom_with_uri", false, "sbom has URI", docWithURICheck},
	{string(bsiv2), "sbom_with_signature", false, "sbom has signature", docWithSignatureCheck},

	// semantic
	{string(semantic), "sbom_required_fields", false, "sbom has all required fields", docWithRequiredFieldCheck},
	{string(semantic), "comp_with_licenses", false, "components have licenses", compWithLicensesCheck},
	{string(semantic), "comp_with_checksums", false, "components have checksums", compWithChecksumsCheck},

	// quality
	{string(quality), "comp_valid_licenses", false, "components with valid licenses", compWithValidLicensesCheck},
	{string(quality), "comp_with_primary_purpose", false, "components with primary purpose", compWithPrimaryPackageCheck},
	{string(quality), "comp_with_deprecated_licenses", false, "components with deprecated licenses", compWithNoDepLicensesCheck},
	{string(quality), "comp_with_restrictive_licenses", false, "components with restrictive_licenses", compWithRestrictedLicensesCheck},
	{string(quality), "comp_with_any_vuln_lookup_id", false, "components with any vulnerability lookup id", compWithAnyLookupIDCheck},
	{string(quality), "comp_with_multi_vuln_lookup_id", false, "components with multiple vulnerability lookup id", compWithMultipleIDCheck},
	{string(quality), "sbom_with_creator_and_version", false, "sbom has creator and version", docWithCreatorCheck},
	{string(quality), "sbom_with_primary_component", false, "sbom has primary component", docWithPrimaryComponentCheck},

	// sharing
	{string(sharing), "sbom_sharable", false, "sbom document has a sharable license", sharableLicenseCheck},
}
