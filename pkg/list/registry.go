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

import (
	"github.com/interlynk-io/sbomqs/v2/pkg/list/extractors"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// ProfileBSIV11 is the profile key for BSI TR-03183-2 v1.1.
const ProfileBSIV11 = "bsiv11"

// ProfileBSIV20 is the profile key for BSI TR-03183-2 v2.0.
const ProfileBSIV20 = "bsiv20"

// ProfileBSIV21 is the profile key for BSI TR-03183-2 v2.1.
const ProfileBSIV21 = "bsiv21"

// ProfileFSCT is the profile key for FSCT Framing 3rd Edition.
const ProfileFSCT = "fsct"

// ProfileInterlynk is the profile key for the Interlynk scoring profile.
const ProfileInterlynk = "interlynk"

// fsctCompExtractors maps FSCT feature keys to per-component extractors.
// Features without the standard comp_/sbom_ prefix are routed via profile-aware dispatch.
var fsctCompExtractors = map[string]extractors.CompExtractor{
	"comp_identity":        extractors.FSCTCompIdentity,
	"supplier_attribution": extractors.FSCTCompSupplier,
	"comp_unique_id":       extractors.FSCTCompUniqID,
	"artifact_integrity":   extractors.FSCTCompHash,
	"license_coverage":     extractors.FSCTCompLicense,
	"copyright_coverage":   extractors.FSCTCompCopyright,
}

// fsctDocExtractors maps FSCT feature keys to SBOM-level extractors.
var fsctDocExtractors = map[string]extractors.DocExtractor{
	"sbom_provenance":        extractors.FSCTSBOMProvenance,
	"sbom_primary_component": extractors.FSCTSBOMPrimaryComponent,
	"relationships_coverage": extractors.FSCTSBOMRelationships,
}

// LookupFSCTCompExtractor returns the FSCT per-component extractor for the given feature key.
func LookupFSCTCompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := fsctCompExtractors[feature]
	return e, ok
}

// LookupFSCTDocExtractor returns the FSCT document-level extractor for the given feature key.
func LookupFSCTDocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := fsctDocExtractors[feature]
	return e, ok
}

// ProfileNTIA is the profile key for NTIA Minimum Elements (2021).
const ProfileNTIA = "ntia"

// ntiaCompExtractors maps NTIA 2021 feature keys to per-component extractors.
var ntiaCompExtractors = map[string]extractors.CompExtractor{
	"comp_supplier": extractors.NTIACompSupplier,
	"comp_name":     extractors.BSIV21CompName,
	"comp_version":  extractors.BSIV21CompVersion,
	"comp_uniq_id":  extractors.BSIV20CompOtherIdentifiers, // PURLs + CPEs
}

// ntiaDocExtractors maps NTIA 2021 feature keys to SBOM-level extractors.
var ntiaDocExtractors = map[string]extractors.DocExtractor{
	"sbom_authors":        extractors.NTIASBOMAuthors,
	"sbom_relationships":  extractors.NTIASBOMRelationships,
	"sbom_timestamp":      extractors.BSIV21SBOMTimestamp,
}

// LookupNTIACompExtractor returns the NTIA per-component extractor for the given feature key.
func LookupNTIACompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := ntiaCompExtractors[feature]
	return e, ok
}

// LookupNTIADocExtractor returns the NTIA document-level extractor for the given feature key.
func LookupNTIADocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := ntiaDocExtractors[feature]
	return e, ok
}

// bsiV11CompExtractors maps BSI v1.1 feature keys to per-component extractors.
// All features reuse existing BSIV21* or BSIV20* extractors since the list command
// shows values rather than enforcing algorithm requirements.
var bsiV11CompExtractors = map[string]extractors.CompExtractor{
	// Required fields
	"comp_creator": extractors.BSIV21CompCreator,
	"comp_name":    extractors.BSIV21CompName,
	"comp_version": extractors.BSIV21CompVersion,
	"comp_depth":   extractors.BSIV21CompDepth,
	"comp_license": extractors.BSIV20CompAssociatedLicense, // concluded preferred, declared fallback
	"comp_hash":    extractors.BSIV21CompDeployableHash,    // distribution extrefs; list shows any hash
	// Additional fields
	"comp_unique_identifiers": extractors.BSIV20CompOtherIdentifiers, // PURLs + CPEs (same as v2.0; SWIDs added in v2.1)
	"comp_source_url":         extractors.BSIV21CompSourceCodeURL,
	"comp_executable_url":     extractors.BSIV21CompDownloadURL,
	"comp_source_hash":        extractors.BSIV21CompSourceHash,
}

// bsiV11DocExtractors maps BSI v1.1 feature keys to SBOM-level extractors.
var bsiV11DocExtractors = map[string]extractors.DocExtractor{
	"sbom_creator":   extractors.BSIV21SBOMCreator,
	"sbom_timestamp": extractors.BSIV21SBOMTimestamp,
	"sbom_uri":       extractors.BSIV20SBOMURI, // GetURI() only (no GetNamespace() fallback)
}

// LookupBSIV11CompExtractor returns the BSI v1.1 per-component extractor for the given feature key.
func LookupBSIV11CompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := bsiV11CompExtractors[feature]
	return e, ok
}

// LookupBSIV11DocExtractor returns the BSI v1.1 document-level extractor for the given feature key.
func LookupBSIV11DocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := bsiV11DocExtractors[feature]
	return e, ok
}

// bsiV20CompExtractors maps BSI v2.0 feature keys to per-component extractors.
// Features identical in logic to v2.1 reuse the BSIV21* extractors directly.
var bsiV20CompExtractors = map[string]extractors.CompExtractor{
	// Required fields
	"comp_creator":              extractors.BSIV21CompCreator,
	"comp_name":                 extractors.BSIV21CompName,
	"comp_version":              extractors.BSIV21CompVersion,
	"comp_filename":             extractors.BSIV21CompFilename,
	"comp_depth":                extractors.BSIV21CompDepth,
	"comp_associated_license":   extractors.BSIV20CompAssociatedLicense,
	"comp_deployable_hash":      extractors.BSIV21CompDeployableHash,
	"comp_executable_property":  extractors.BSIV21CompExecutableProp,
	"comp_archive_property":     extractors.BSIV21CompArchiveProp,
	"comp_structured_property":  extractors.BSIV21CompStructuredProp,
	// Additional fields
	"comp_source_code_url":   extractors.BSIV21CompSourceCodeURL,
	"comp_download_url":      extractors.BSIV21CompDownloadURL,
	"comp_other_identifiers": extractors.BSIV20CompOtherIdentifiers,
	"comp_concluded_license": extractors.BSIV20CompConcludedLicense,
	// Optional fields
	"comp_declared_license": extractors.BSIV20CompDeclaredLicense,
	"comp_source_hash":      extractors.BSIV21CompSourceHash,
}

// bsiV20DocExtractors maps BSI v2.0 feature keys to SBOM-level extractors.
var bsiV20DocExtractors = map[string]extractors.DocExtractor{
	"sbom_creator":   extractors.BSIV21SBOMCreator,
	"sbom_timestamp": extractors.BSIV21SBOMTimestamp,
	"sbom_uri":       extractors.BSIV20SBOMURI,
}

// LookupBSIV20CompExtractor returns the BSI v2.0 per-component extractor for the given feature key.
func LookupBSIV20CompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := bsiV20CompExtractors[feature]
	return e, ok
}

// LookupBSIV20DocExtractor returns the BSI v2.0 document-level extractor for the given feature key.
func LookupBSIV20DocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := bsiV20DocExtractors[feature]
	return e, ok
}

// bsiV21CompExtractors maps BSI v2.1 feature keys to per-component extractors.
var bsiV21CompExtractors = map[string]extractors.CompExtractor{
	"comp_creator":              extractors.BSIV21CompCreator,
	"comp_name":                 extractors.BSIV21CompName,
	"comp_version":              extractors.BSIV21CompVersion,
	"comp_filename":             extractors.BSIV21CompFilename,
	"comp_depth":                extractors.BSIV21CompDepth,
	"comp_distribution_license": extractors.BSIV21CompDistributionLicense,
	"comp_deployable_hash":      extractors.BSIV21CompDeployableHash,
	"comp_executable_prop":      extractors.BSIV21CompExecutableProp,
	"comp_archive_prop":         extractors.BSIV21CompArchiveProp,
	"comp_structured_prop":      extractors.BSIV21CompStructuredProp,
	"comp_source_code_url":      extractors.BSIV21CompSourceCodeURL,
	"comp_download_url":         extractors.BSIV21CompDownloadURL,
	"comp_other_identifiers":    extractors.BSIV21CompOtherIdentifiers,
	"comp_original_licenses":    extractors.BSIV21CompOriginalLicenses,
	"comp_effective_license":    extractors.BSIV21CompEffectiveLicense,
	"comp_source_hash":          extractors.BSIV21CompSourceHash,
	"comp_security_txt_url":     extractors.BSIV21CompSecurityTxtURL,
}

// bsiV21DocExtractors maps BSI v2.1 feature keys to SBOM-level extractors.
var bsiV21DocExtractors = map[string]extractors.DocExtractor{
	"sbom_spec_version": extractors.BSIV21SpecVersion,
	"sbom_creator":      extractors.BSIV21SBOMCreator,
	"sbom_timestamp":    extractors.BSIV21SBOMTimestamp,
	"sbom_uri":          extractors.BSIV21SBOMURI,
}

// LookupBSIV21CompExtractor returns the BSI v2.1 per-component extractor for the given feature key.
func LookupBSIV21CompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := bsiV21CompExtractors[feature]
	return e, ok
}

// LookupBSIV21DocExtractor returns the BSI v2.1 document-level extractor for the given feature key.
func LookupBSIV21DocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := bsiV21DocExtractors[feature]
	return e, ok
}

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
	// Identity
	"comp_name":    compOnly(evaluateCompWithName),
	"comp_version": compOnly(evaluateCompWithVersion),
	"comp_supplier": docAndComp(extractors.GenericCompSupplier),
	"comp_uniq_ids": docAndComp(extractors.GenericCompUniqIDs),
	"comp_local_id": docAndComp(evaluateCompWithLocalID),
	"comp_author":   docAndComp(extractors.GenericCompAuthor),
	"comp_purl":     compOnly(evaluateCompWithPURL),
	"comp_cpe":      compOnly(evaluateCompWithCPE),
	"comp_primary_purpose": docAndComp(evaluateCompWithPrimaryPurpose),
	"comp_external_refs":   docAndComp(extractors.GenericCompExternalRefs),
	// Relationships
	"comp_depth":        docAndComp(extractors.GenericCompDepth),
	"comp_dependencies": compOnly(evaluateCompWithDependencies),
	// Integrity & checksums
	"comp_checksums":         compOnly(evaluateCompWithChecksums),
	"comp_sha256":            compOnly(evaluateCompWithChecksums256),
	"comp_checksums_sha256":  compOnly(evaluateCompWithSHA256Checksums),
	"comp_strong_checksums":  compOnly(evaluateCompWithStrongChecksums),
	"comp_weak_checksums":    compOnly(evaluateCompWithWeakChecksums),
	"comp_source_code_hash":  docAndComp(evaluateCompWithSourceCodeHash),
	// Source & executable
	"comp_source_code_uri": docAndComp(evaluateCompWithSourceCodeURI),
	"comp_executable_uri":  compOnly(evaluateCompWithExecutableURI),
	// Licensing
	"comp_licenses":             compOnly(evaluateCompWithLicenses),
	"comp_valid_licenses":       compOnly(evaluateCompWithValidLicenses),
	"comp_all_licenses":         docAndComp(extractors.GenericCompAllLicenses),
	"comp_associated_license":   docAndComp(evaluateCompWithAssociatedLicense),
	"comp_concluded_license":    compOnly(evaluateCompWithConcludedLicense),
	"comp_declared_license":     compOnly(evaluateCompWithDeclaredLicense),
	"comp_deprecated_licenses":  compOnly(evaluateCompWithDeprecatedLicenses),
	"comp_restrictive_licenses": compOnly(evaluateCompWithRestrictedLicenses),
	// Security
	"comp_any_vuln_lookup_id":   compOnly(evaluateCompWithAnyVulnLookupID),
	"comp_multi_vuln_lookup_id": compOnly(evaluateCompWithMultiVulnLookupID),
	"comp_copyright":            compOnly(evaluateCompWithCopyright),
}

var compFeatureAliases = map[string]string{
	// backwards compat: old comp_with_* → new canonical
	"comp_with_name":                 "comp_name",
	"pack_name":                      "comp_name",
	"comp_with_version":              "comp_version",
	"pack_version":                   "comp_version",
	"comp_with_supplier":             "comp_supplier",
	"comp_generic_supplier":          "comp_supplier",
	"comp_with_uniq_ids":             "comp_uniq_ids",
	"comp_uniq_id":                   "comp_uniq_ids",
	"comp_unique_identifiers":        "comp_uniq_ids",
	"comp_with_uniq_id":              "comp_uniq_ids",
	"comp_with_local_id":             "comp_local_id",
	"comp_with_local_ids":            "comp_local_id",
	"comp_with_purl":                 "comp_purl",
	"comp_with_cpe":                  "comp_cpe",
	"comp_with_purpose":              "comp_primary_purpose",
	"comp_purpose":                   "comp_primary_purpose",
	"comp_with_primary_purpose":      "comp_primary_purpose",
	"comp_generic_depth":             "comp_depth",
	"comp_with_dependencies":         "comp_dependencies",
	"comp_with_checksums":            "comp_checksums",
	"comp_hash":                      "comp_checksums",
	"comp_with_sha256":               "comp_sha256",
	"comp_hash_sha256":               "comp_sha256",
	"comp_with_checksums_sha256":     "comp_checksums_sha256",
	"comp_with_strong_checksums":     "comp_strong_checksums",
	"comp_with_weak_checksums":       "comp_weak_checksums",
	"comp_with_source_code_hash":     "comp_source_code_hash",
	"comp_source_hash":               "comp_source_code_hash",
	"comp_with_source_code":          "comp_source_code_uri",
	"comp_with_source_code_uri":      "comp_source_code_uri",
	"comp_source_code_url":           "comp_source_code_uri",
	"comp_with_executable_uri":       "comp_executable_uri",
	"comp_download_url":              "comp_executable_uri",
	"pack_download_url":              "comp_executable_uri",
	"comp_with_licenses":             "comp_licenses",
	"comp_with_valid_licenses":       "comp_valid_licenses",
	"comp_license":                   "comp_all_licenses",
	"comp_with_associated_license":   "comp_associated_license",
	"comp_with_concluded_license":    "comp_concluded_license",
	"pack_license_con":               "comp_concluded_license",
	"comp_with_declared_license":     "comp_declared_license",
	"comp_with_declared_licenses":    "comp_declared_license",
	"pack_license_dec":               "comp_declared_license",
	"comp_with_deprecated_licenses":  "comp_deprecated_licenses",
	"comp_no_deprecated_licenses":    "comp_deprecated_licenses",
	"comp_with_restrictive_licenses": "comp_restrictive_licenses",
	"comp_no_restrictive_licenses":   "comp_restrictive_licenses",
	"comp_with_any_vuln_lookup_id":   "comp_any_vuln_lookup_id",
	"comp_with_multi_vuln_lookup_id": "comp_multi_vuln_lookup_id",
	"comp_with_copyright":            "comp_copyright",
	"pack_copyright":                 "comp_copyright",
}

type sbomFeatureEval func(sbom.Document) (bool, string, error)

var sbomFeatureAliases = map[string]string{
	"comp_primary_comp":              "sbom_primary_comp",
	"comp_with_primary_comp":         "sbom_primary_comp",
	"sbom_timestamp":                 "sbom_creation_timestamp",
	"sbom_creator":                   "sbom_authors",
	"sbom_data_license":              "sbom_license",
	"sbom_build_process":             "sbom_build",
	"sbom_lifecycle":                 "sbom_build",
	// sbom_tool → sbom_creator_and_version (renamed from sbom_with_creator_and_version)
	"sbom_tool":                      "sbom_creator_and_version",
	"sbom_tool_version":              "sbom_creator_and_version",
	"sbom_with_creator_and_version":  "sbom_creator_and_version", // backwards compat
	// sbom_primary_component is now canonical; keep sbom_with_ as compat alias
	"sbom_with_primary_component":    "sbom_primary_component",   // backwards compat
	"sbom_depth":                     "sbom_dependencies",
	"sbom_spec_declared":             "sbom_spec",
	"sbom_name":                      "sbom_spec",
	"sbom_file_format":               "sbom_spec_file_format",
	"sbom_machine_format":            "sbom_spec_file_format",
	// sbom_uri is now canonical; keep sbom_with_uri as compat alias
	"sbom_with_uri":                  "sbom_uri",                 // backwards compat
	"sbom_namespace":                 "sbom_uri",
	// sbom_vuln is now canonical
	"sbom_vulnerabilities":           "sbom_vuln",
	"sbom_with_vuln":                 "sbom_vuln",                // backwards compat
	// sbom_bomlinks is now canonical
	"sbom_with_bomlinks":             "sbom_bomlinks",            // backwards compat
	"sbom_with_comment":              "sbom_comment",
	// spec_version_compliant is now canonical
	"spec_with_version_compliant":    "spec_version_compliant",   // backwards compat
}

var sbomFeatureRegistry = map[string]sbomFeatureEval{
	"sbom_creation_timestamp":  evaluateSBOMTImestamp,
	"sbom_authors":             evaluateSBOMAuthors,
	"sbom_build":               evaluateSBOMBuildLifeCycle,
	"sbom_creator_and_version": evaluateSBOMWithCreatorAndVersion, // was sbom_with_creator_and_version
	"sbom_primary_component":   evaluateSBOMPrimaryComponent,      // was sbom_with_primary_component
	"sbom_dependencies":        evaluateSBOMDependencies,
	"sbom_sharable":            evaluateSBOMSharable,
	"sbom_parsable":            evaluateSBOMParsable,
	"sbom_spec":                evaluateSBOMSpec,
	"sbom_spec_file_format":    evaluateSBOMMachineFormat,
	"sbom_spec_version":        evaluateSBOMSpecVersion,
	"spec_version_compliant":   evaluateSBOMSpecVersionCompliant,  // was spec_with_version_compliant
	"sbom_uri":                 evaluateSBOMWithURI,               // was sbom_with_uri
	"sbom_vuln":                evaluateSBOMWithVulnerability,     // was sbom_with_vuln
	"sbom_bomlinks":            evaluateSBOMWithBomLinks,          // was sbom_with_bomlinks
	"sbom_spdxid":              evaluateSBOMSPDXID,
	"sbom_organization":        evaluateSBOMOrganization,
	"sbom_schema_valid":        evaluateSBOMSchema,
	"sbom_license":             evaluateSBOMLicense,
	"sbom_comment":             evaluateSBOMComment,
	"sbom_supplier":            evaluateSBOMSupplier,
	"sbom_completeness_declared": evaluateSBOMCompleteness,
	"sbom_primary_comp":        extractors.GenericSBOMPrimaryComp,
}

// interlynkCompExtractors maps Interlynk feature keys to per-component extractors.
var interlynkCompExtractors = map[string]extractors.CompExtractor{
	// Identification
	"comp_name":     extractors.BSIV21CompName,
	"comp_version":  extractors.BSIV21CompVersion,
	"comp_local_id": extractors.InterlynkCompLocalID,
	// Integrity
	"comp_checksums": extractors.InterlynkCompChecksums,
	"comp_sha256":    extractors.InterlynkCompSHA256,
	// Completeness
	"comp_dependencies":    extractors.InterlynkCompDependencies,
	"comp_source_code":     extractors.InterlynkCompSourceCode,
	"comp_supplier":        extractors.InterlynkCompSupplier,
	"comp_purpose":         extractors.InterlynkCompPurpose,
	// Licensing
	"comp_licenses":               extractors.InterlynkCompLicenses,
	"comp_valid_licenses":         extractors.InterlynkCompValidLicenses,
	"comp_no_deprecated_licenses": extractors.InterlynkCompNoDeprecatedLicenses,
	"comp_no_restrictive_licenses": extractors.InterlynkCompNoRestrictiveLicenses,
	"comp_declared_licenses":      extractors.InterlynkCompDeclaredLicenses,
	// Vulnerability
	"comp_purl": extractors.InterlynkCompPURL,
	"comp_cpe":  extractors.InterlynkCompCPE,
}

// interlynkDocExtractors maps Interlynk feature keys to SBOM-level extractors.
var interlynkDocExtractors = map[string]extractors.DocExtractor{
	// Provenance
	"sbom_timestamp": extractors.BSIV21SBOMTimestamp,
	"sbom_authors":   extractors.InterlynkSBOMAuthors,
	"sbom_tool":      extractors.InterlynkSBOMTool,
	"sbom_supplier":  extractors.InterlynkSBOMSupplier,
	"sbom_namespace": extractors.InterlynkSBOMNamespace,
	"sbom_lifecycle": extractors.InterlynkSBOMLifecycle,
	// Integrity
	"sbom_signature": extractors.InterlynkSBOMSignature,
	// Completeness
	"sbom_completeness":      extractors.InterlynkSBOMCompleteness,
	"sbom_primary_component": extractors.InterlynkSBOMPrimaryComponent,
	// Licensing
	"sbom_data_license": extractors.InterlynkSBOMDataLicense,
	// Structural
	"sbom_spec_declared": extractors.InterlynkSBOMSpecDeclared,
	"sbom_spec_version":  extractors.InterlynkSBOMSpecVersion,
	"sbom_file_format":   extractors.InterlynkSBOMFileFormat,
	"sbom_schema_valid":  extractors.InterlynkSBOMSchemaValid,
}

// IsKnownFeature reports whether key is a recognised generic feature name or alias.
// This is used by the CLI to validate --feature values before dispatching.
func IsKnownFeature(key string) bool {
	if _, ok := compFeatureRegistry[key]; ok {
		return true
	}
	if _, ok := compFeatureAliases[key]; ok {
		return true
	}
	if _, ok := sbomFeatureRegistry[key]; ok {
		return true
	}
	if _, ok := sbomFeatureAliases[key]; ok {
		return true
	}
	return false
}

// LookupInterlynkCompExtractor returns the Interlynk per-component extractor for the given feature key.
func LookupInterlynkCompExtractor(feature string) (extractors.CompExtractor, bool) {
	e, ok := interlynkCompExtractors[feature]
	return e, ok
}

// LookupInterlynkDocExtractor returns the Interlynk document-level extractor for the given feature key.
func LookupInterlynkDocExtractor(feature string) (extractors.DocExtractor, bool) {
	e, ok := interlynkDocExtractors[feature]
	return e, ok
}
