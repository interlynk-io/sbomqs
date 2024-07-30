// Copyright 2023 Interlynk.io
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
	strucutral category = "Structural"
	ntiam      category = "NTIA-minimum-elements"
	semantic   category = "Semantic"
	quality    category = "Quality"
	sharing    category = "Sharing"
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
	{string(strucutral), "sbom_spec", false, "SBOM Specification", specCheck},
	{string(strucutral), "sbom_spec_version", false, "Spec Version", specVersionCheck},
	{string(strucutral), "sbom_spec_file_format", false, "Spec File Format", specFileFormatCheck},
	{string(strucutral), "sbom_parsable", false, "Spec is parsable", specParsableCheck},

	// ntia minimum
	{string(ntiam), "comp_with_supplier", false, "components have suppliers", compSupplierCheck},
	{string(ntiam), "comp_with_name", false, "components have a name", compWithNameCheck},
	{string(ntiam), "comp_with_version", false, "components have a version", compWithVersionCheck},
	{string(ntiam), "comp_with_uniq_ids", false, "components have uniq ids", compWithUniqIDCheck},
	{string(ntiam), "sbom_dependencies", false, "sbom has dependencies", docWithDepedenciesCheck},
	{string(ntiam), "sbom_authors", false, "sbom has authors", docWithAuthorsCheck},
	{string(ntiam), "sbom_creation_timestamp", false, "sbom has creation timestamp", docWithTimeStampCheck},

	// semantic
	{string(semantic), "sbom_required_fields", false, "sbom has all required fields", docWithRequiredFieldCheck},
	{string(semantic), "comp_with_licenses", false, "components have licenses", compWithLicensesCheck},
	{string(semantic), "comp_with_checksums", false, "components have checksums", compWithChecksumsCheck},

	// quality
	{string(quality), "comp_valid_licenses", false, "components with valid licenses", compWithValidLicensesCheck},
	{string(quality), "comp_with_primary_purpose", false, "components with primary purpose", compWithPrimaryPackageCheck},
	{string(quality), "comp_with_deprecated_licenses", false, "components with deprecated licenses", compWithNoDepLicensesCheck},
	{string(quality), "comp_with_restrictive_licenses", false, "components with restrictive_licenses", compWithRestrictedLicensesCheck},
	{string(quality), "comp_with_any_vuln_lookup_id", false, "components with any vulnerability lookup id", compWithAnyLookupIdCheck},
	{string(quality), "comp_with_multi_vuln_lookup_id", false, "components with multiple vulnerability lookup id", compWithMultipleIdCheck},
	{string(quality), "sbom_with_creator_and_version", false, "sbom has creator and version", docWithCreatorCheck},
	{string(quality), "sbom_with_primary_component", false, "sbom has primary component", docWithPrimaryComponentCheck},

	// sharing
	{string(sharing), "sbom_sharable", false, "sbom document has a sharable license", sharableLicenseCheck},
}
