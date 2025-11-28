// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package list

import "github.com/interlynk-io/sbomqs/v2/pkg/sbom"

type compFeatureEval func(sbom.GetComponent, sbom.Document) (bool, string, error)

// functions that only take (comp) the component
func compOnly(fn func(sbom.GetComponent) (bool, string, error)) compFeatureEval {
	return func(c sbom.GetComponent, _ sbom.Document) (bool, string, error) {
		return fn(c)
	}
}

// functions that take (doc, comp) in that order
func docAndComp(fn func(sbom.Document, sbom.GetComponent) (bool, string, error)) compFeatureEval {
	return func(c sbom.GetComponent, d sbom.Document) (bool, string, error) {
		return fn(d, c)
	}
}

var compFeatureRegistry = map[string]compFeatureEval{
	"comp_with_name":                 compOnly(evaluateCompWithName),
	"comp_with_version":              compOnly(evaluateCompWithVersion),
	"comp_with_supplier":             compOnly(evaluateCompWithSupplier),
	"comp_with_uniq_ids":             compOnly(evaluateCompWithUniqID),
	"comp_with_local_id":             compOnly(evaluateCompWithLocalID),
	"comp_valid_licenses":            compOnly(evaluateCompWithValidLicenses),
	"comp_with_checksums_sha256":     compOnly(evaluateCompWithSHA256Checksums),
	"comp_with_source_code_uri":      docAndComp(evaluateCompWithSourceCodeURI),
	"comp_with_source_code_hash":     docAndComp(evaluateCompWithSourceCodeHash),
	"comp_with_executable_uri":       compOnly(evaluateCompWithExecutableURI),
	"comp_with_associated_license":   docAndComp(evaluateCompWithAssociatedLicense),
	"comp_with_concluded_license":    compOnly(evaluateCompWithConcludedLicense),
	"comp_with_declared_license":     compOnly(evaluateCompWithDeclaredLicense),
	"comp_with_dependencies":         compOnly(evaluateCompWithDependencies),
	"comp_with_any_vuln_lookup_id":   compOnly(evaluateCompWithAnyVulnLookupID),
	"comp_with_deprecated_licenses":  compOnly(evaluateCompWithDeprecatedLicenses),
	"comp_with_multi_vuln_lookup_id": compOnly(evaluateCompWithMultiVulnLookupID),
	"comp_with_primary_purpose":      docAndComp(evaluateCompWithPrimaryPurpose),
	"comp_with_restrictive_licenses": compOnly(evaluateCompWithRestrictedLicenses),
	"comp_with_checksums":            compOnly(evaluateCompWithChecksums),
	"comp_with_sha256":               compOnly(evaluateCompWithChecksums256),
	"comp_with_licenses":             compOnly(evaluateCompWithLicenses),
	"comp_with_purl":                 compOnly(evaluateCompWithPURL),
	"comp_with_cpe":                  compOnly(evaluateCompWithCPE),
	// "comp_with_copyright":            compOnly(evaluateCompWithCopyright),
}

var compFeatureAliases = map[string]string{
	"comp_name":                    "comp_with_name",
	"pack_name":                    "comp_with_name",
	"comp_version":                 "comp_with_version",
	"pack_version":                 "comp_with_version",
	"comp_supplier":                "comp_with_supplier",
	"comp_license":                 "comp_valid_licenses",
	"comp_uniq_id":                 "comp_with_uniq_ids",
	"comp_unique_identifiers":      "comp_with_uniq_ids",
	"comp_with_uniq_id":            "comp_with_uniq_ids",
	"comp_with_source_code":        "comp_with_source_code_uri",
	"comp_source_code_uri":         "comp_with_source_code_uri",
	"comp_source_code_url":         "comp_with_source_code_uri",
	"comp_download_url":            "comp_with_executable_uri",
	"pack_download_url":            "comp_with_executable_uri",
	"comp_source_hash":             "comp_with_source_code_hash",
	"comp_associated_license":      "comp_with_associated_license",
	"comp_with_declared_licenses":  "comp_with_declared_license",
	"pack_license_dec":             "comp_with_declared_license",
	"pack_license_con":             "comp_with_concluded_license",
	"comp_dependencies":            "comp_with_dependencies",
	"comp_depth":                   "comp_with_dependencies",
	"comp_no_deprecated_licenses":  "comp_with_deprecated_licenses",
	"comp_no_restrictive_licenses": "comp_with_deprecated_licenses",
	"comp_with_purpose":            "comp_with_primary_purpose",
	"comp_purpose":                 "comp_with_primary_purpose",
	"comp_hash":                    "comp_with_checksums",
	"comp_hash_sha256":             "comp_with_sha256",
	"comp_with_valid_licenses":     "comp_with_licenses",
	"comp_purl":                    "comp_with_purl",
	"comp_cpe":                     "comp_with_cpe",
	"pack_copyright":               "comp_with_copyright",
}

type sbomFeatureEval func(sbom.Document) (bool, string, error)

var sbomFeatureAliases = map[string]string{
	"sbom_timestamp":         "sbom_creation_timestamp",
	"sbom_creator":           "sbom_authors",
	"sbom_data_license":      "sbom_license",
	"sbom_build_process":     "sbom_build",
	"sbom_lifecycle":         "sbom_build",
	"sbom_tool":              "sbom_with_creator_and_version",
	"sbom_tool_version":      "sbom_with_creator_and_version",
	"sbom_primary_component": "sbom_with_primary_component",
	"sbom_depth":             "sbom_dependencies",
	"sbom_spec_declared":     "sbom_spec",
	"sbom_name":              "sbom_spec",
	"sbom_file_format":       "sbom_spec_file_format",
	"sbom_machine_format":    "sbom_spec_file_format",
	"sbom_uri":               "sbom_with_uri",
	"sbom_namespace":         "sbom_with_uri",
	"sbom_vulnerabilities":   "sbom_with_vuln",
	"sbom_bomlinks":          "sbom_with_bomlinks",
	"sbom_with_comment":      "sbom_comment",
}

var sbomFeatureRegistry = map[string]sbomFeatureEval{
	"sbom_creation_timestamp":       evaluateSBOMTImestamp,
	"sbom_authors":                  evaluateSBOMAuthors,
	"sbom_build":                    evaluateSBOMBuildLifeCycle,
	"sbom_with_creator_and_version": evaluateSBOMWithCreatorAndVersion,
	"sbom_with_primary_component":   evaluateSBOMPrimaryComponent,
	"sbom_dependencies":             evaluateSBOMDependencies,
	"sbom_sharable":                 evaluateSBOMSharable,
	"sbom_parsable":                 evaluateSBOMParsable,
	"sbom_spec":                     evaluateSBOMSpec,
	"sbom_spec_file_format":         evaluateSBOMMachineFormat,
	"sbom_spec_version":             evaluateSBOMSpecVersion,
	"spec_with_version_compliant":   evaluateSBOMSpecVersionCompliant,
	"sbom_with_uri":                 evaluateSBOMWithURI,
	"sbom_with_vuln":                evaluateSBOMWithVulnerability,
	"sbom_with_bomlinks":            evaluateSBOMWithBomLinks,
	"sbom_spdxid":                   evaluateSBOMSPDXID,
	"sbom_organization":             evaluateSBOMOrganization,
	"sbom_schema_valid":             evaluateSBOMSchema,
	"sbom_license":                  evaluateSBOMLicense,
	"sbom_comment":                  evaluateSBOMComment,
	"sbom_supplier":                 evaluateSBOMSupplier,
}
