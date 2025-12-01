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

package registry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/extractors"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/profiles"
)

// ComprCatKey lists all comprehenssive catefories
// e.g. identification, provenance, integrity, etc
const (
	CatIdentification         catalog.ComprCatKey = "identification"
	CatProvenance             catalog.ComprCatKey = "provenance"
	CatIntegrity              catalog.ComprCatKey = "integrity"
	CatCompleteness           catalog.ComprCatKey = "completeness"
	CatLicensingAndCompliance catalog.ComprCatKey = "licensing_and_compliance"
	CatVulnerabilityAndTrace  catalog.ComprCatKey = "vulnerability_and_traceability"
	CatStructural             catalog.ComprCatKey = "structural"
	CatComponentQualityInfo   catalog.ComprCatKey = "component_quality_info" // weight 0
)

var NTIAKeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_machine_format": profiles.SBOMAutomationSpec,
	"comp_name":           profiles.CompName,
	"comp_version":        profiles.CompVersion,
	"comp_uniq_id":        profiles.CompWithUniqID,
	"sbom_dependencies":   profiles.SBOMDepedencies,
	"sbom_creator":        profiles.SBOMAuthors,
	"sbom_timestamp":      profiles.SBOMCreationTimestamp,
}

var NTIA2025KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_machine_format":  profiles.SBOMAutomationSpec,
	"sbom_author":          profiles.SBOMAuthors,
	"software_producer":    profiles.NTIA2025SoftwareProducer,
	"comp_name":            profiles.CompName,
	"comp_version":         profiles.CompVersion,
	"software_identifiers": profiles.NTIA2025CompSoftwareIdentifiers,
	"comp_hash":            profiles.NTIA2025CompHash,
	"license":              profiles.NTIA2025CompLicense,
	"sbom_dependencies":    profiles.SBOMDepedencies,
	"comp_supplier":        profiles.CompSupplier,
	"tool_name":            profiles.NTIA2025ToolName,
	"sbom_timestamp":       profiles.SBOMCreationTimestamp,
	"generation_context":   profiles.NTIA2025GenerationContext,
}

var BSIV11KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":         profiles.SBOMAutomationSpec,
	"sbom_spec_version": profiles.BSISBOMSpecVersion,
	"sbom_build":        profiles.BSISBOMBuildLifecycle,
	"sbom_depth":        profiles.SBOMDepedencies,
	"sbom_creator":      profiles.SBOMAuthors,
	"sbom_timestamp":    profiles.SBOMCreationTimestamp,
	"sbom_uri":          profiles.BSISBOMNamespace,

	"comp_name":    profiles.CompName,
	"comp_version": profiles.CompVersion,

	"comp_license":         profiles.BSICompWithLicenses,
	"comp_hash":            profiles.BSICompWithHash,
	"comp_source_code_url": profiles.BSICompWithSourceCodeURI,
	"comp_download_url":    profiles.BSICompWithDownloadURI,
	"comp_source_hash":     profiles.BSICompWithSourceCodeHash,
	"comp_depth":           profiles.BSICompWithDependency,
}

var BSIV20KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":         profiles.SBOMAutomationSpec,
	"sbom_spec_version": profiles.BSISBOMSpecVersion,
	"sbom_build":        profiles.BSISBOMBuildLifecycle,
	"sbom_depth":        profiles.SBOMDepedencies,
	"sbom_creator":      profiles.SBOMAuthors,
	"sbom_timestamp":    profiles.SBOMCreationTimestamp,
	"sbom_uri":          profiles.BSISBOMNamespace,

	"comp_name":    profiles.CompName,
	"comp_version": profiles.CompVersion,

	"comp_license":         profiles.BSICompWithLicenses,
	"comp_hash":            profiles.BSICompWithHash,
	"comp_source_code_url": profiles.BSICompWithSourceCodeURI,
	"comp_download_url":    profiles.BSICompWithDownloadURI,
	"comp_source_hash":     profiles.BSICompWithSourceCodeHash,
	"comp_depth":           profiles.BSICompWithDependency,

	"sbom_signature":          profiles.BSISBOMWithSignature,
	"sbom_bomlinks":           profiles.BSISBOMWithBomLinks,
	"sbom_vulnerabilities":    profiles.BSISBOMWithVulnerabilities,
	"comp_hash_sha256":        profiles.CompSHA256Plus,
	"comp_associated_license": profiles.BSICompWithAssociatedLicenses,
}

var OCTV11KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":              profiles.OCTV11SBOMSpec,
	"sbom_spec_version":      profiles.OCTV11SBOMSpecVersion,
	"sbom_data_license":      profiles.OCTV11SBOMDataLicense,
	"sbom_identifier":        profiles.OCTV11SBOMIdentifier,
	"sbom_name":              profiles.OCTV11SBOMName,
	"sbom_namespace":         profiles.OCTV11SBOMNamespace,
	"sbom_creator":           profiles.OCTV11SBOMCreator,
	"sbom_timestamp":         profiles.OCTV11SBOMTimestamp,
	"sbom_creator_comment":   profiles.OCTV11SBOMCreatorComment,
	"comp_name":              profiles.OCTV11CompName,
	"comp_identifier":        profiles.OCTV11CompIdentifier,
	"comp_version":           profiles.OCTV11CompVersion,
	"comp_supplier":          profiles.OCTV11CompSupplier,
	"comp_download_location": profiles.OCTV11CompDownloadLocation,
	"comp_license_concluded": profiles.OCTV11CompLicenseConcluded,
	"comp_license_declared":  profiles.OCTV11CompLicenseDeclared,
	"comp_copyright":         profiles.OCTV11CompCopyright,
	"sbom_relationships":     profiles.OCTV11SBOMRelationships,
	"comp_checksum":          profiles.OCTV11CompChecksum,
	"comp_purl":              profiles.OCTV11CompPURL,
}

var InterlynkKeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"comp_name":     profiles.InterCompWithName,
	"comp_version":  profiles.InterCompWithVersion,
	"comp_local_id": profiles.InterCompWithUniqueID,

	"sbom_timestamp": profiles.InterSBOMTimestamp,
	"sbom_authors":   profiles.InterSBOMAuthors,
	"sbom_tool":      profiles.InterSBOMTOol,
	"sbom_supplier":  profiles.InterSBOMSupplier,
	"sbom_namespace": profiles.InterSBOMNamespace,
	"sbom_lifecycle": profiles.InterSBOMLifecycle,

	"comp_checksums": profiles.InterCompWithChecksum,
	"comp_sha256":    profiles.InterCompWithChecksum265,
	"sbom_signature": profiles.InterSBOMSignature,

	"comp_dependencies":      profiles.InterCompWithDependencies,
	"sbom_completeness":      profiles.InterSBOMCompleteness,
	"sbom_primary_component": profiles.InterSBOMPrimaryComponent,
	"comp_source_code":       profiles.InterCompWithSourceCode,
	"comp_supplier":          profiles.InterCompWithSupplier,
	"comp_purpose":           profiles.InterCompWithPurpose,

	"comp_licenses":                profiles.InterCompWithLicenses,
	"comp_valid_licenses":          profiles.InterCompWithValidLicenses,
	"comp_no_deprecated_licenses":  profiles.InterCompWithNODeprecatedLicenses,
	"comp_no_restrictive_licenses": profiles.InterCompWithNORestrictiveLicenses,
	"comp_declared_licenses":       profiles.InterCompWithDeclaredLicenses,
	"sbom_data_license":            profiles.InterSBOMDataLicenses,

	"comp_purl": profiles.InterCompWithPURL,
	"comp_cpe":  profiles.InterCompWithCPE,

	"sbom_spec_declared": profiles.InterSBOMSpec,
	"sbom_spec_version":  profiles.InterSBOMSpecVersion,
	"sbom_file_format":   profiles.InterSBOMFileFormat,
	"sbom_schema_valid":  profiles.InterSBOMSchema,
}

var CompKeyToEvaluatingFunction = map[string]catalog.ComprFeatEval{
	"comp_with_name":     extractors.CompWithName,
	"comp_with_version":  extractors.CompWithVersion,
	"comp_with_local_id": extractors.CompWithUniqLocalIDs,

	"sbom_creation_timestamp": extractors.SBOMCreationTimestamp,
	"sbom_authors":            extractors.SBOMAuthors,
	"sbom_tool_version":       extractors.SBOMCreationTool,
	"sbom_supplier":           extractors.SBOMSupplier,
	"sbom_namespace":          extractors.SBOMNamespace,
	"sbom_lifecycle":          extractors.SBOMLifeCycle,

	"comp_with_strong_checksums": extractors.CompWithStrongChecksums,
	"comp_with_weak_checksums":   extractors.CompWithWeakChecksums,
	"sbom_signature":             extractors.SBOMSignature,

	"comp_with_dependencies":     extractors.CompWithDependencies,
	"sbom_completeness_declared": extractors.CompWithCompleteness,
	"sbom_primary_component":     extractors.SBOMWithPrimaryComponent,
	"comp_with_source_code":      extractors.CompWithSourceCode,
	"comp_with_supplier":         extractors.CompWithSupplier,
	"comp_with_purpose":          extractors.CompWithPackagePurpose,

	"comp_with_licenses":           extractors.CompWithLicenses,
	"comp_with_valid_licenses":     extractors.CompWithValidLicenses,
	"comp_no_deprecated_licenses":  extractors.CompWithDeprecatedLicenses,
	"comp_no_restrictive_licenses": extractors.CompWithRestrictiveLicenses,
	"comp_with_declared_licenses":  extractors.CompWithDeclaredLicenses,
	"sbom_data_license":            extractors.SBOMDataLicense,

	"comp_with_purl": extractors.CompWithPURL,
	"comp_with_cpe":  extractors.CompWithCPE,

	"sbom_spec_declared": extractors.SBOMWithSpec,
	"sbom_spec_version":  extractors.SBOMSpecVersion,
	"sbom_file_format":   extractors.SBOMFileFormat,
	"sbom_schema_valid":  extractors.SBOMSchemaValid,
}

// ProfileKey lists all profiles
// e.g. ntia, bsi-v1.1, bsi-v2.0, oct-v1.1, etc
const (
	ProfileNTIA      catalog.ProfileKey = "ntia"
	ProfileNTIA2025  catalog.ProfileKey = "ntia-2025"
	ProfileBSI11     catalog.ProfileKey = "bsi-v1.1"
	ProfileBSI20     catalog.ProfileKey = "bsi-v2.0"
	ProfileOCTV11    catalog.ProfileKey = "oct-v1.1"
	ProfileInterlynk catalog.ProfileKey = "interlynk"
)

var categoryAlias = map[string]catalog.ComprCatKey{
	"identification":                 CatIdentification,
	"provenance":                     CatProvenance,
	"integrity":                      CatIntegrity,
	"completeness":                   CatCompleteness,
	"licensing":                      CatLicensingAndCompliance,
	"licensingandcompliance":         CatLicensingAndCompliance,
	"licensing_and_compliance":       CatLicensingAndCompliance,
	"vulnerability":                  CatVulnerabilityAndTrace,
	"vulnerabilityandtraceability":   CatVulnerabilityAndTrace,
	"vulnerability_and_traceability": CatVulnerabilityAndTrace,
	"structural":                     CatStructural,
	"componentquality(info)":         CatComponentQualityInfo,
	"component_quality_info":         CatComponentQualityInfo,
}

var profileAliases = map[string]catalog.ProfileKey{
	"ntia":                  ProfileNTIA,
	"nita-minimum-elements": ProfileNTIA,
	"NTIA-minimum-elements": ProfileNTIA,
	"NTIA-Minimum-Elements": ProfileNTIA,
	"NTIA":                  ProfileNTIA,
	"ntia-2025":             ProfileNTIA2025,
	"NTIA-2025":             ProfileNTIA2025,
	"ntia2025":              ProfileNTIA2025,
	"NTIA2025":              ProfileNTIA2025,
	"BSI":                   ProfileBSI11,
	"bsi":                   ProfileBSI11,
	"BSI-V1.1":              ProfileBSI11,
	"bsi-v1.1":              ProfileBSI11,
	"bsi-v1_1":              ProfileBSI11,
	"BSI-V2.0":              ProfileBSI20,
	"bsi-v2.0":              ProfileBSI20,
	"OCT-V1.1":              ProfileOCTV11,
	"oct-v1.1":              ProfileOCTV11,
	"OpenChain-Telco-v1.1":  ProfileOCTV11,
}

// Returns an error on serious IO / decode failures only.
func InitializeCatalog(ctx context.Context, conf config.Config) (*catalog.Catalog, error) {
	log := logger.FromContext(ctx)
	log.Debugf("InitializeCatalog: starting catalog initialization")

	catal := &catalog.Catalog{}
	confFile := strings.TrimSpace(conf.ConfigFile)

	// when config file is feeded
	if confFile != "" {
		log.Debugf("InitializeCatalog: config file provided: %q", confFile)

		categories, profiles, err := mergeConfigFileIntoCatalogYAML(ctx, confFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", confFile, err)
		}

		if categories != nil {
			log.Debugf("InitializeCatalog: loaded %d comprehensive category(ies) from config file", len(categories))
			catal.ComprCategories = categories
		}

		if profiles != nil {
			log.Debugf("InitializeCatalog: loaded %d profile(s) from config file", len(profiles))
			catal.Profiles = profiles
		}

		log.Debugf("InitializeCatalog: initialized from config file %q", confFile)
		return catal, nil
	}

	// Profiles provided command inline
	if len(conf.Profile) > 0 {
		log.Debugf("InitializeCatalog: profiles provided inline (%d): %v", len(conf.Profile), conf.Profile)

		profiles, err := filterProfiles(ctx, conf.Profile)
		if err != nil {
			return nil, err
		}
		catal.Profiles = profiles
		log.Debugf("InitializeCatalog: selected %d profile(s) after filtering", len(catal.Profiles))

		return catal, nil
	}

	// Features provided inline
	if len(conf.Features) > 0 {
		log.Debugf("InitializeCatalog: features provided inline (%d) - applying feature-based initialization", len(conf.Features))
		return catal, nil
	}

	// Categories provided inline
	if len(conf.Categories) > 0 {
		log.Debugf("InitializeCatalog: categories provided inline (%d): %v", len(conf.Categories), conf.Categories)
		catal.ComprCategories = filterCategories(ctx, conf.Categories)

		log.Debugf("InitializeCatalog: selected %d comprehensive category(ies) after filtering", len(catal.ComprCategories))
		return catal, nil
	}

	catal.ComprCategories = comprehenssiveCategories
	catal.Profiles = defaultProfiles

	// Default -> use full comprehensive categories
	log.Debugf("InitializeCatalog: no config/profile/categories provided - defaulting to %d comprehensive categories", len(catal.ComprCategories))

	// Final summary
	log.Debugf("InitializeCatalog: finished initialization: profiles=%d, comprehensiveCategories=%d",
		len(catal.Profiles), len(catal.ComprCategories))

	return catal, nil
}

// mergeConfigFileIntoCatalogYAML reads path and merges any found categories/profiles into out.
// It tries to detect which shape the file has by looking for top-level keys.
func mergeConfigFileIntoCatalogYAML(ctx context.Context, path string) ([]catalog.ComprCatSpec, []catalog.ProfSpec, error) {
	log := logger.FromContext(ctx)
	log.Debugf("mergeConfigFileIntoCatalogYAML: processing file %q", path)

	var cat []catalog.ComprCatSpec
	var prof []catalog.ProfSpec

	// #nosec G304 -- User-provided paths are expected for CLI tool
	b, err := os.ReadFile(path)
	if err != nil {
		log.Errorf("mergeConfigFileIntoCatalogYAML: failed to read file %q: %v", path, err)
		return nil, nil, err
	}

	log.Debugf("mergeConfigFileIntoCatalogYAML: read %d bytes from %q", len(b), path)

	lower := strings.ToLower(string(b))

	// Detect comprehensive categories file
	if strings.Contains(lower, "categories:") {
		log.Debugf("mergeConfigFileIntoCatalogYAML: detected comprehensive categories config in %q", path)

		cat, err = ReadComprConfigFile(path)
		if err != nil {
			log.Errorf("mergeConfigFileIntoCatalogYAML: failed to parse comprehensive config %q: %v", path, err)
			return nil, nil, fmt.Errorf("read comprehensive config: %w", err)
		}

		log.Debugf("mergeConfigFileIntoCatalogYAML: parsed %d comprehensive categories from %q", len(cat), path)
		return cat, nil, nil
	}

	if strings.Contains(lower, "profiles:") {
		log.Debugf("mergeConfigFileIntoCatalogYAML: detected profiles config in %q", path)

		prof, err = ReadProfileConfigFile(path)
		if err != nil {
			log.Errorf("mergeConfigFileIntoCatalogYAML: failed to parse profiles config %q: %v", path, err)
			return nil, nil, fmt.Errorf("read profile config: %w", err)
		}

		log.Debugf("mergeConfigFileIntoCatalogYAML: parsed %d profiles from %q", len(prof), path)
		return nil, prof, nil
	}

	log.Debugf("mergeConfigFileIntoCatalogYAML: no top-level 'categories:' or 'profiles:' key found in %q config file", path)

	return nil, nil, fmt.Errorf("Unknown config file, neither categories not profiles based")
}

// filterCategories keeps only requested comprehensive categories.
func filterCategories(ctx context.Context, categories []string) []catalog.ComprCatSpec {
	log := logger.FromContext(ctx)
	log.Debugf("filterCategories: received %d categories: %v", len(categories), categories)

	alreadyExists := make(map[string]bool)
	var finalCats []catalog.ComprCatSpec
	var unknown []string

	for _, cat := range categories {
		if cat == "" {
			continue
		}

		category := strings.ToLower(strings.TrimSpace(cat))
		if alreadyExists[category] {
			log.Debugf("filterCategories: duplicate category: %q - skip", category)
			continue
		}
		alreadyExists[category] = true

		switch category {
		case "identification":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatIdentificationSpec)

		case "provenance":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatProvenanceSpec)

		case "integrity":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatIntegritySpec)

		case "completeness":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatCompletenessSpec)

		case "licensing":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatLicensingAndComplianceSpec)

		case "vulnerability":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatVulnerabilityAndTraceSpec)

		case "structural":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatStructuralSpec)

		case "compinfo":
			log.Debugf("filterCategories: selecting category %q", category)
			finalCats = append(finalCats, CatComponentQualityInfoSpec)

		default:
			unknown = append(unknown, category)
			log.Debugf("filterCategories: unknown category %q - skipping", category)
		}
	}

	log.Debugf("filterCategories: selected %d categories: %v", len(finalCats), finalCats)
	if len(unknown) > 0 {
		log.Debugf("filterCategories: ignored %d unknown categories: %v", len(unknown), unknown)
	}

	return finalCats
}

// filterProfiles keeps only requested profile keys (preserving order).
func filterProfiles(ctx context.Context, profiles []string) ([]catalog.ProfSpec, error) {
	log := logger.FromContext(ctx)
	log.Debugf("filterProfiles: received %d requested profiles: %v", len(profiles), profiles)

	alreadyExists := make(map[string]bool)
	finalProfiles := make([]catalog.ProfSpec, 0, len(profiles))
	var unknown []string

	for _, pro := range profiles {
		if pro == "" {
			continue
		}

		profile := strings.ToLower(strings.TrimSpace(pro))
		if alreadyExists[profile] {
			log.Debugf("filterProfiles: duplicate profile: %q, skipping", profile)
			continue
		}
		alreadyExists[profile] = true

		switch profile {

		case "ntia":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileNTIASpec)

		case "ntia-2025":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileNTIA2025Spec)

		case "bsi":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileBSI11Spec)

		case "bsi-v1.1":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileBSI11Spec)

		case "bsi-v2.0":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileBSI20Spec)

		case "oct-v1.1":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileOCTV11Spec)

		case "interlynk":
			log.Debugf("filterProfiles: selecting profile %q", profile)
			finalProfiles = append(finalProfiles, profileInterlynkSpec)

		default:
			unknown = append(unknown, profile)
			log.Debugf("filterProfiles: unknown profile %q, skip", profile)
		}

	}
	log.Debugf("filterProfiles: selected %d profile(s): %v", len(finalProfiles), finalProfiles)
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown profile(s): %v", unknown)
	}

	return finalProfiles, nil
}

var CatIdentificationSpec = catalog.ComprCatSpec{
	Key:         "identification",
	Name:        "Identification",
	Weight:      10,
	Description: "Identification of components is critical for understanding supply chain metadata",
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_with_name", Name: "Component With Name", Weight: 0.40, Ignore: false, Evaluate: extractors.CompWithName},
		{Key: "comp_with_version", Name: "Component With Version", Weight: 0.35, Ignore: false, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
		{Key: "comp_with_local_id", Name: "Component With Local IDs", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithUniqLocalIDs},
	},
}

var CatProvenanceSpec = catalog.ComprCatSpec{
	Key:         "provenance",
	Name:        "Provenance",
	Description: "Enables trust and audit trails",
	Weight:      12,
	Features: []catalog.ComprFeatSpec{
		{Key: "sbom_creation_timestamp", Name: "Document Creation Time", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTimestamp},
		{Key: "sbom_authors", Name: "Document Authors", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMAuthors},
		{Key: "sbom_tool_version", Name: "Document Creator Tool & Version", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTool},
		{Key: "sbom_supplier", Name: "Document Supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMSupplier},
		{Key: "sbom_namespace", Name: "Document URI/Namespace", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMNamespace},
		{Key: "sbom_lifecycle", Name: "Document Lifecycle", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMLifeCycle},
	},
}

var CatIntegritySpec = catalog.ComprCatSpec{
	Key:         "integrity",
	Name:        "Integrity",
	Description: "Allows for verification if artifacts were altered",
	Weight:      15,
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_with_strong_checksums", Name: "Component With Strong Checksums", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithStrongChecksums},
		{Key: "comp_with_weak_checksums", Name: "Component With Weak Checksums", Weight: 0.40, Ignore: false, Evaluate: extractors.CompWithWeakChecksums},
		{Key: "sbom_signature", Name: "Document Signature", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMSignature},
	},
}

var CatCompletenessSpec = catalog.ComprCatSpec{
	Key:         "completeness",
	Name:        "Completeness",
	Description: "Allows for vulnerability and impact analysis",
	Weight:      12,
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_with_dependencies", Name: "Component With Dependencies", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithDependencies},
		{Key: "sbom_completeness_declared", Name: "Component With Declared Completeness", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithCompleteness},
		{Key: "sbom_primary_component", Name: "Primary Component", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMWithPrimaryComponent},
		{Key: "comp_with_source_code", Name: "Component With Source Code", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSourceCode},
		{Key: "comp_with_supplier", Name: "Component With Supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSupplier},
		{Key: "comp_with_purpose", Name: "Component With Primary Purpose", Weight: 0.10, Ignore: false, Evaluate: extractors.CompWithPackagePurpose},
	},
}

var CatLicensingAndComplianceSpec = catalog.ComprCatSpec{
	Key:         "licensing_and_compliance",
	Name:        "Licensing",
	Description: "Determines redistribution rights and legal compliance",
	Weight:      15,
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_with_licenses", Name: "Components With Licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithLicenses},
		{Key: "comp_with_valid_licenses", Name: "Component With Valid Licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithValidLicenses},
		{Key: "comp_no_deprecated_licenses", Name: "Component Without Deprecated Licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeprecatedLicenses},
		{Key: "comp_no_restrictive_licenses", Name: "Component Without Restrictive Licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithRestrictiveLicenses},
		{Key: "comp_with_declared_licenses", Name: "Component With Original Licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeclaredLicenses},
		{Key: "sbom_data_license", Name: "Document Data License", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMDataLicense},
	},
}

var CatVulnerabilityAndTraceSpec = catalog.ComprCatSpec{
	Key:         "vulnerability_and_traceability",
	Name:        "Vulnerability",
	Description: "Ability to map components to vulnerability databases",
	Weight:      10,
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_with_purl", Name: "Component With PURL", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithPURL},
		{Key: "comp_with_cpe", Name: "Component With CPE", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithCPE},
	},
}

var CatStructuralSpec = catalog.ComprCatSpec{
	Key:         "structural",
	Name:        "Structural",
	Description: "If a BOM can't be reliably parsed, all downstream automation fails",
	Weight:      8,
	Features: []catalog.ComprFeatSpec{
		{Key: "sbom_spec_declared", Name: "SBOM Spec", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMWithSpec},
		{Key: "sbom_spec_version", Name: "SBOM Spec Version", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMSpecVersion},
		{Key: "sbom_file_format", Name: "SBOM File Format", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMFileFormat},
		{Key: "sbom_schema_valid", Name: "Schema Validation", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMSchemaValid},
	},
}

var CatComponentQualityInfoSpec = catalog.ComprCatSpec{
	Key:         "compinfo",
	Name:        "Component Quality",
	Weight:      10,
	Description: "Real-time component risk assessment based on external threat intelligence. These metrics are informational only and do NOT affect the overall quality score",
	Features: []catalog.ComprFeatSpec{
		{Key: "comp_eol_eos", Name: "Component No Longer Maintained or Declared EOL", Weight: 0.10, Ignore: true, Evaluate: extractors.CompWithEOSOrEOL},
		{Key: "comp_malicious", Name: "Component tagged as malicious in threat databases", Weight: 0.30, Ignore: true, Evaluate: extractors.CompWithMalicious},
		{Key: "comp_vuln_sev_critical", Name: "Component with vulnerabilities in CISA's Known Exploited Vulns", Weight: 0.30, Ignore: true, Evaluate: extractors.CompWithVulnSeverityCritical},
		{Key: "comp_kev", Name: "Component which are actively exploited", Weight: 0.30, Ignore: true, Evaluate: extractors.CompWithKev},
		{Key: "comp_purl_valid", Name: "Component purl resolves to a package manager or repository", Weight: 0.30, Ignore: true, Evaluate: extractors.CompWithPurlValid},
		{Key: "comp_cpe_valid", Name: "Component cpe is found in NVD CPE database", Weight: 0.30, Ignore: true, Evaluate: extractors.CompWithCpeValid},
	},
}

var comprehenssiveCategories = []catalog.ComprCatSpec{
	CatIdentificationSpec,
	CatProvenanceSpec,
	CatIntegritySpec,
	CatCompletenessSpec,
	CatLicensingAndComplianceSpec,
	CatVulnerabilityAndTraceSpec,
	CatStructuralSpec,
	CatComponentQualityInfoSpec,
}

var defaultProfiles = []catalog.ProfSpec{
	profileInterlynkSpec,
	profileNTIASpec,
	profileNTIA2025Spec,
	profileBSI11Spec,
	profileOCTV11Spec,
}

var profileInterlynkSpec = catalog.ProfSpec{
	Key:         ProfileInterlynk,
	Name:        "Interlynk",
	Description: "Interlynk Scoring Profile",
	Features: []catalog.ProfFeatSpec{
		{Key: "comp_name", Name: "Component Name", Description: "components with name", Required: true, Evaluate: profiles.InterCompWithName},
		{Key: "comp_version", Name: "Component Version", Description: "components with version", Required: true, Evaluate: profiles.InterCompWithVersion},
		{Key: "comp_local_id", Name: "Component Local IDs", Description: "components with local identifiers", Required: true, Evaluate: profiles.InterCompWithUniqueID},

		{Key: "sbom_timestamp", Name: "SBOM Creation Tome", Description: "Document creation time", Required: true, Evaluate: profiles.InterSBOMTimestamp},
		{Key: "sbom_authors", Name: "SBOM Authors", Description: "Document authors", Required: true, Evaluate: profiles.InterSBOMAuthors},
		{Key: "sbom_tool", Name: "SBOM Creation Tool", Description: "Document creator tool & version", Required: true, Evaluate: profiles.InterSBOMTOol},
		{Key: "sbom_supplier", Name: "SBOM Supplier", Description: "Document supplier", Required: true, Evaluate: profiles.InterSBOMSupplier},
		{Key: "sbom_namespace", Name: "SBOM Namespace", Description: "Document URI/namespace", Required: true, Evaluate: profiles.InterSBOMNamespace},
		{Key: "sbom_lifecycle", Name: "SBOM Lifecycle", Description: "Document Lifecycle", Required: true, Evaluate: profiles.InterSBOMLifecycle},

		{Key: "comp_checksums", Name: "Component Chekcsum", Description: "components with checksums", Required: true, Evaluate: profiles.InterCompWithChecksum},
		{Key: "comp_sha256", Name: "Component Checksum SHA256", Description: "components with SHA-256+", Required: true, Evaluate: profiles.InterCompWithChecksum265},
		{Key: "sbom_signature", Name: "SBOM Signature", Description: "Document signature	", Required: true, Evaluate: profiles.InterSBOMSignature},

		{Key: "comp_dependencies", Name: "Component Dependencies", Description: "components with dependencies", Required: true, Evaluate: profiles.InterCompWithDependencies},
		{Key: "sbom_completeness", Name: "SBOM Completeness ", Description: "components with declared completeness", Required: true, Evaluate: profiles.InterSBOMCompleteness},
		{Key: "sbom_primary_component", Name: "Primary Component", Description: "Primary component identified", Required: true, Evaluate: profiles.InterSBOMPrimaryComponent},
		{Key: "comp_source_code", Name: "Component Source Code", Description: "components with source code", Required: true, Evaluate: profiles.InterCompWithSourceCode},
		{Key: "comp_supplier", Name: "Component Supplier", Description: "components with supplier", Required: true, Evaluate: profiles.InterCompWithSupplier},
		{Key: "comp_purpose", Name: "Component Type", Description: "components with primary purpose", Required: true, Evaluate: profiles.InterCompWithPurpose},

		{Key: "comp_licenses", Name: "Component License", Description: "components with licenses", Required: true, Evaluate: profiles.InterCompWithLicenses},
		{Key: "comp_valid_licenses", Name: "Component Valid License", Description: "components with valid licenses", Required: true, Evaluate: profiles.InterCompWithValidLicenses},
		{Key: "comp_no_deprecated_licenses", Name: "Component With No Deprecated License", Description: "components without deprecated licenses", Required: true, Evaluate: profiles.InterCompWithNODeprecatedLicenses},
		{Key: "comp_no_restrictive_licenses", Name: "Component With No Restrictive License", Description: "components without restrictive licenses", Required: true, Evaluate: profiles.InterCompWithNORestrictiveLicenses},
		{Key: "comp_declared_licenses", Name: "Component Declared License", Description: "components with original licenses", Required: true, Evaluate: profiles.InterCompWithDeclaredLicenses},
		{Key: "sbom_data_license", Name: "SBOM Data License", Description: "Document data license", Required: true, Evaluate: profiles.InterSBOMDataLicenses},

		{Key: "comp_purl", Name: "Component PURL", Description: "components with PURL", Required: true, Evaluate: profiles.InterCompWithPURL},
		{Key: "comp_cpe", Name: "Component CPE", Description: "components with CPE", Required: true, Evaluate: profiles.InterCompWithCPE},

		{Key: "sbom_spec_declared", Name: "SBOM Spec", Description: "SBOM spec declared", Required: true, Evaluate: profiles.InterSBOMSpec},
		{Key: "sbom_spec_version", Name: "SBOM Spec Version", Description: "SBOM spec version", Required: true, Evaluate: profiles.InterSBOMSpecVersion},
		{Key: "sbom_file_format", Name: "SBOM File Format", Description: "SBOM file format", Required: true, Evaluate: profiles.InterSBOMFileFormat},
		{Key: "sbom_schema_valid", Name: "SBOM Schema", Description: "Schema validation", Required: true, Evaluate: profiles.InterSBOMSchema},
	},
}

var profileNTIASpec = catalog.ProfSpec{
	Key:         ProfileNTIA,
	Name:        "NTIA Minimum Elements (2021)",
	Description: "NTIA Minimum Elements Profile",
	Features: []catalog.ProfFeatSpec{
		// Required (SHALL) fields
		{Key: "sbom_machine_format", Name: "Automation Support", Required: true, Description: "Valid spec (SPDX/CycloneDX) and format (JSON/XML)", Evaluate: profiles.SBOMAutomationSpec},
		{Key: "comp_supplier", Name: "Supplier Name", Required: true, Description: "Component supplier information", Evaluate: profiles.CompWithSupplier},
		{Key: "comp_name", Name: "Component Name", Required: true, Description: "All components must have names", Evaluate: profiles.CompName},
		{Key: "comp_version", Name: "Component Version", Required: true, Description: "Version strings for all components", Evaluate: profiles.CompVersion},
		{Key: "comp_uniq_id", Name: "Component Other Identifiers", Required: true, Description: "PURL, CPE, or other unique IDs", Evaluate: profiles.CompWithUniqID},
		{Key: "sbom_dependencies", Name: "Dependency Relationships", Required: true, Description: "Component dependency mapping", Evaluate: profiles.SBOMDepedencies},
		{Key: "sbom_creator", Name: "SBOM Author", Required: true, Description: "Tool or person who created SBOM", Evaluate: profiles.SBOMAuthors},
		{Key: "sbom_timestamp", Name: "SBOM Timestamp", Required: true, Description: "ISO 8601 creation timestamp", Evaluate: profiles.SBOMCreationTimestamp},
		// Optional (SHOULD) fields - don't impact score
		{Key: "comp_hash", Name: "Component Hash", Required: false, Description: "Component checksums (optional)", Evaluate: profiles.NTIACompHash},
		{Key: "sbom_lifecycle", Name: "Lifecycle Phase", Required: false, Description: "SBOM lifecycle phase (optional)", Evaluate: profiles.NTIASBOMLifecycle},
		{Key: "comp_relationships", Name: "Other Component Relationships", Required: false, Description: "Additional relationships (optional)", Evaluate: profiles.NTIACompRelationships},
		{Key: "comp_license", Name: "License Information", Required: false, Description: "Component licenses (optional)", Evaluate: profiles.NTIACompLicense},
	},
}

var profileNTIA2025Spec = catalog.ProfSpec{
	Key:         ProfileNTIA2025,
	Name:        "NTIA Minimum Elements (2025) - RFC",
	Description: "NTIA Minimum Elements 2025 Profile (RFC - Request for Comments)",
	Features: []catalog.ProfFeatSpec{
		{Key: "sbom_machine_format", Name: "Machine-Readable Formats", Required: true, Description: "Valid spec (SPDX/CycloneDX) and format (JSON/XML)", Evaluate: profiles.SBOMAutomationSpec},
		{Key: "sbom_author", Name: "SBOM Author", Required: true, Description: "Tool or person who created SBOM", Evaluate: profiles.SBOMAuthors},
		{Key: "software_producer", Name: "Software Producer", Required: true, Description: "Entity that produced the software", Evaluate: profiles.NTIA2025SoftwareProducer},
		{Key: "comp_name", Name: "Component Name", Required: true, Description: "All components must have names", Evaluate: profiles.CompName},
		{Key: "comp_version", Name: "Component Version", Required: true, Description: "Version strings for all components", Evaluate: profiles.CompVersion},
		{Key: "software_identifiers", Name: "Software Identifiers", Required: true, Description: "SPDX ID, PURL, CPE, or SWID", Evaluate: profiles.NTIA2025CompSoftwareIdentifiers},
		{Key: "comp_hash", Name: "Component Hash", Required: true, Description: "Checksums for all components", Evaluate: profiles.NTIA2025CompHash},
		{Key: "license", Name: "License", Required: true, Description: "License information for components", Evaluate: profiles.NTIA2025CompLicense},
		{Key: "sbom_dependencies", Name: "Dependency Relationship", Required: true, Description: "Component dependency mapping", Evaluate: profiles.SBOMDepedencies},
		{Key: "comp_supplier", Name: "Component Supplier", Required: true, Description: "Supplier information for components", Evaluate: profiles.CompSupplier},
		{Key: "tool_name", Name: "Tool Name", Required: true, Description: "Name of the tool that created SBOM", Evaluate: profiles.NTIA2025ToolName},
		{Key: "sbom_timestamp", Name: "Timestamp", Required: true, Description: "ISO 8601 creation timestamp", Evaluate: profiles.SBOMCreationTimestamp},
		{Key: "generation_context", Name: "Generation Context", Required: true, Description: "Context of SBOM generation", Evaluate: profiles.NTIA2025GenerationContext},
	},
}

var profileBSI11Spec = catalog.ProfSpec{
	Key:         ProfileBSI11,
	Name:        "BSI TR-03183-2 v1.1",
	Description: "BSI TR-03183-2 v1.1 Profile",
	Features: []catalog.ProfFeatSpec{
		{Key: "sbom_spec", Name: "SBOM Formats", Required: true, Description: "SPDX or CycloneDX", Evaluate: profiles.SBOMSpec},
		{Key: "sbom_spec_version", Name: "SBOM Spec Version", Required: true, Description: "Valid supported version", Evaluate: profiles.BSISBOMSpecVersion},
		{Key: "sbom_build", Name: "Build Information", Required: false, Description: "Build phase indication", Evaluate: profiles.BSISBOMBuildLifecycle},
		{Key: "sbom_depth", Name: "SBOM Depth", Required: true, Description: "Complete dependency tree", Evaluate: profiles.SBOMDepedencies},
		{Key: "sbom_creator", Name: "Creator Info", Required: true, Description: "Contact email/URL", Evaluate: profiles.SBOMAuthors},
		{Key: "sbom_timestamp", Name: "Creation Time", Required: true, Description: "Valid timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
		{Key: "sbom_uri", Name: "URI/Namespace", Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},

		{Key: "comp_name", Name: "Component Name", Required: true, Description: "All components named", Evaluate: profiles.CompName},
		{Key: "comp_version", Name: "Component Version", Required: true, Description: "Version for each component", Evaluate: profiles.CompVersion},

		{Key: "comp_license", Name: "Component License", Required: true, Description: "License information", Evaluate: profiles.BSICompWithLicenses},
		{Key: "comp_hash", Name: "Component Hash", Required: true, Description: "Checksums for components", Evaluate: profiles.BSICompWithHash},
		{Key: "comp_source_code_url", Name: "Component Source URL", Required: false, Description: "Source code repository", Evaluate: profiles.BSICompWithSourceCodeURI},
		{Key: "comp_download_url", Name: "Component Download URL", Required: true, Description: "Where to obtain component", Evaluate: profiles.BSICompWithDownloadURI},
		{Key: "comp_source_hash", Name: "Component Source Hash", Required: false, Description: "Hash of source code", Evaluate: profiles.BSICompWithSourceCodeHash},
		{Key: "comp_depth", Name: "Component Dependencies", Required: true, Description: "Dependency relationships", Evaluate: profiles.BSICompWithDependency},
	},
}

var profileBSI20Spec = catalog.ProfSpec{
	Key:         ProfileBSI20,
	Name:        "BSI TR-03183-2 v2.0",
	Description: "BSI TR-03183-2 v2.0 Profile",
	Features: []catalog.ProfFeatSpec{
		{Key: "sbom_spec", Name: "SBOM Formats", Required: true, Description: "SPDX or CycloneDX", Evaluate: profiles.SBOMSpec},
		{Key: "sbom_spec_version", Name: "SBOM Spec Version", Required: true, Description: "Valid supported version", Evaluate: profiles.BSISBOMSpecVersion},
		{Key: "sbom_build", Name: "Build Information", Required: false, Description: "Build phase indication", Evaluate: profiles.BSISBOMBuildLifecycle},
		{Key: "sbom_depth", Name: "SBOM Depth", Required: true, Description: "Complete dependency tree", Evaluate: profiles.SBOMDepedencies},
		{Key: "sbom_creator", Name: "Creator Info", Required: true, Description: "Contact email/URL", Evaluate: profiles.SBOMAuthors},
		{Key: "sbom_timestamp", Name: "Creation Time", Required: true, Description: "Valid timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
		{Key: "sbom_uri", Name: "URI/Namespace", Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},

		{Key: "comp_name", Name: "Component Name", Required: true, Description: "All components named", Evaluate: profiles.CompName},
		{Key: "comp_version", Name: "Component Version", Required: true, Description: "Version for each component", Evaluate: profiles.CompVersion},

		{Key: "comp_license", Name: "Component License", Required: true, Description: "License information", Evaluate: profiles.BSICompWithLicenses},
		{Key: "comp_hash", Name: "Component Hash", Required: true, Description: "Checksums for components", Evaluate: profiles.BSICompWithHash},
		{Key: "comp_source_code_url", Name: "Component Source URL", Required: false, Description: "Source code repository", Evaluate: profiles.BSICompWithSourceCodeURI},
		{Key: "comp_download_url", Name: "Component Download URL", Required: true, Description: "Where to obtain component", Evaluate: profiles.BSICompWithDownloadURI},
		{Key: "comp_source_hash", Name: "Component Source Hash", Required: false, Description: "Hash of source code", Evaluate: profiles.BSICompWithSourceCodeHash},
		{Key: "comp_depth", Name: "Component Dependencies", Required: true, Description: "Dependency relationships", Evaluate: profiles.BSICompWithDependency},

		{Key: "sbom_signature", Name: "Digital Signature", Required: true, Description: "Cryptographic signature verification", Evaluate: profiles.BSISBOMWithSignature},
		{Key: "sbom_bomlinks", Name: "External References", Required: false, Description: "Links to other SBOMs", Evaluate: profiles.BSISBOMWithBomLinks},
		{Key: "sbom_vulnerabilities", Name: "Vulnerability Info", Required: false, Description: "Known vulnerabilities (absence preferred)", Evaluate: profiles.BSISBOMWithVulnerabilities},
		{Key: "comp_hash_sha256", Name: "SHA-256 Checksums", Required: true, Description: "SHA-256 or stronger required", Evaluate: profiles.CompSHA256Plus},
		{Key: "comp_associated_license", Name: "License Validation", Required: true, Description: "Valid SPDX license identifiers", Evaluate: profiles.BSICompWithAssociatedLicenses},
	},
}

var profileOCTV11Spec = catalog.ProfSpec{
	Key:         ProfileOCTV11,
	Name:        "OpenChain Telco v1.1",
	Description: "OpenChain Telco SBOM Guide v1.1 Profile",
	Features: []catalog.ProfFeatSpec{
		// Document Creation Information - SHALL
		{Key: "sbom_spec", Name: "SBOM Format", Required: true, Description: "SPDX or CycloneDX format", Evaluate: profiles.OCTV11SBOMSpec},
		{Key: "sbom_spec_version", Name: "Spec Version", Required: true, Description: "Valid spec version", Evaluate: profiles.OCTV11SBOMSpecVersion},
		{Key: "sbom_data_license", Name: "Data License", Required: true, Description: "License for SBOM data", Evaluate: profiles.OCTV11SBOMDataLicense},
		{Key: "sbom_identifier", Name: "Document Identifier", Required: true, Description: "SPDX ID or serial number", Evaluate: profiles.OCTV11SBOMIdentifier},
		{Key: "sbom_name", Name: "Document Name", Required: true, Description: "SBOM document name", Evaluate: profiles.OCTV11SBOMName},
		{Key: "sbom_namespace", Name: "Document Namespace", Required: true, Description: "Unique namespace URI", Evaluate: profiles.OCTV11SBOMNamespace},
		{Key: "sbom_creator", Name: "Creator", Required: true, Description: "Organization and tool info", Evaluate: profiles.OCTV11SBOMCreator},
		{Key: "sbom_timestamp", Name: "Created Timestamp", Required: true, Description: "ISO 8601 creation time", Evaluate: profiles.OCTV11SBOMTimestamp},
		{Key: "sbom_creator_comment", Name: "Creator Comment", Required: true, Description: "Build information or lifecycle", Evaluate: profiles.OCTV11SBOMCreatorComment},

		// Package Information - SHALL
		{Key: "comp_name", Name: "Package Name", Required: true, Description: "All components named", Evaluate: profiles.OCTV11CompName},
		{Key: "comp_identifier", Name: "Package Identifier", Required: true, Description: "SPDX ID or bom-ref", Evaluate: profiles.OCTV11CompIdentifier},
		{Key: "comp_version", Name: "Package Version", Required: true, Description: "Version for each component", Evaluate: profiles.OCTV11CompVersion},
		{Key: "comp_supplier", Name: "Package Supplier", Required: true, Description: "Component supplier info", Evaluate: profiles.OCTV11CompSupplier},
		{Key: "comp_download_location", Name: "Download Location", Required: true, Description: "Where to obtain component", Evaluate: profiles.OCTV11CompDownloadLocation},
		{Key: "comp_license_concluded", Name: "License Concluded", Required: true, Description: "Concluded license info", Evaluate: profiles.OCTV11CompLicenseConcluded},
		{Key: "comp_license_declared", Name: "License Declared", Required: true, Description: "Declared license info", Evaluate: profiles.OCTV11CompLicenseDeclared},
		{Key: "comp_copyright", Name: "Copyright Text", Required: true, Description: "Copyright information", Evaluate: profiles.OCTV11CompCopyright},
		{Key: "sbom_relationships", Name: "Relationships", Required: true, Description: "Dependencies and relationships", Evaluate: profiles.OCTV11SBOMRelationships},

		// Package Information - SHOULD
		{Key: "comp_checksum", Name: "Package Checksum", Required: false, Description: "Component checksums", Evaluate: profiles.OCTV11CompChecksum},
		{Key: "comp_purl", Name: "Package URL (PURL)", Required: false, Description: "Package URL identifier", Evaluate: profiles.OCTV11CompPURL},
	},
}

var Profile = []catalog.ProfSpec{
	profileNTIASpec,
	profileNTIA2025Spec,
	profileBSI11Spec,
	profileBSI20Spec,
	profileOCTV11Spec,
	profileInterlynkSpec,
}
