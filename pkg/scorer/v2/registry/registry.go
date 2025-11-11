package registry

import (
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/extractors"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
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
	"sbom_spec":               profiles.SBOMAutomationSpec,
	"comp_name":               profiles.CompName,
	"comp_uniq_id":            profiles.CompWithUniqID,
	"sbom_dependencies":       profiles.SBOMDepedencies,
	"sbom_authors":            profiles.SBOMAuthors,
	"sbom_creation_timestamp": profiles.SBOMCreationTimestamp,
}

var BSIV11KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":               profiles.SBOMAutomationSpec,
	"sbom_spec_version":       profiles.BSISBOMSpecVersion,
	"sbom_lifecycle":          profiles.BSISBOMBuildLifecycle,
	"sbom_dependencies":       profiles.SBOMDepedencies,
	"sbom_authors":            profiles.SBOMAuthors,
	"sbom_creation_timestamp": profiles.SBOMCreationTimestamp,
	"sbom_namespace":          profiles.BSISBOMNamespace,

	"comp_name":    profiles.CompName,
	"comp_version": profiles.CompVersion,

	"comp_license":           profiles.BSICompWithLicenses,
	"comp_hash":              profiles.BSICompWithHash,
	"comp_source_code_url":   profiles.BSICompWithSourceCodeURI,
	"comp_download_code_url": profiles.BSICompWithDownloadURI,
	"comp_source_code_hash":  profiles.BSICompWithSourceCodeHash,
	"comp_dependencies":      profiles.BSICompWithDependency,
}

var BSIV20KeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":               profiles.SBOMAutomationSpec,
	"sbom_spec_version":       profiles.BSISBOMSpecVersion,
	"sbom_lifecycle":          profiles.BSISBOMBuildLifecycle,
	"sbom_dependencies":       profiles.SBOMDepedencies,
	"sbom_authors":            profiles.SBOMAuthors,
	"sbom_creation_timestamp": profiles.SBOMCreationTimestamp,
	"sbom_namespace":          profiles.BSISBOMNamespace,

	"comp_name":    profiles.CompName,
	"comp_version": profiles.CompVersion,

	"comp_license":           profiles.BSICompWithLicenses,
	"comp_hash":              profiles.BSICompWithHash,
	"comp_source_code_url":   profiles.BSICompWithSourceCodeURI,
	"comp_download_code_url": profiles.BSICompWithDownloadURI,
	"comp_source_code_hash":  profiles.BSICompWithSourceCodeHash,
	"comp_dependencies":      profiles.BSICompWithDependency,

	"sbom_signature":          profiles.BSISBOMWithSignature,
	"sbom_bomlinks":           profiles.BSISBOMWithBomLinks,
	"sbom_vulnerabilities":    profiles.BSISBOMWithVulnerabilities,
	"comp_hash_256_sha":       profiles.CompSHA256Plus,
	"comp_associated_license": profiles.BSICompWithAssociatedLicenses,
}

var OCTKeyToEvaluatingFunction = map[string]catalog.ProfFeatEval{
	"sbom_spec":              profiles.OCTSBOMSpec,
	"sbom_spec_version":      profiles.OCTSBOMSpecVersion,
	"comp_name":              profiles.OCTCompWithName,
	"comp_version":           profiles.OCTCompWithVersion,
	"sbom_namespace":         profiles.OCTSBOMNamespace,
	"comp_license_declared":  profiles.OCTCompWithDeclaredLicense,
	"comp_license_concluded": profiles.OCTCompWithConcludedLicense,

	"sbom_license":       profiles.OCTSBOMDataLicense,
	"sbom_creation_tool": profiles.OCTSBOMToolCreation,
	"sbom_spdxid":        profiles.OCTSBOMSpdxID,
	"sbom_name":          profiles.OCTSBOMName,
	"sbom_comment":       profiles.OCTSBOMComment,
	"sbom_organization":  profiles.OCTSBOMCreationOrganization,
	"comp_spdxid":        profiles.OCTCompWithSpdxID,
	"comp_file_analyze":  profiles.OCTCompWithFileAnalyzed,
	"comp_copyright":     profiles.OCTCompWithCopyright,
}

var CompKeyToEvaluatingFunction = map[string]catalog.ComprFeatEval{
	"comp_with_name":        extractors.CompWithName,
	"comp_with_version":     extractors.CompWithVersion,
	"comp_with_identifiers": extractors.CompWithUniqLocalIDs,

	"sbom_creation_timestamp": extractors.SBOMCreationTimestamp,
	"sbom_authors":            extractors.SBOMAuthors,
	"sbom_tool_version":       extractors.SBOMCreationTool,
	"sbom_supplier":           extractors.SBOMSupplier,
	"sbom_namespace":          extractors.SBOMNamespace,
	"sbom_lifecycle":          extractors.SBOMLifeCycle,

	"comp_with_checksums": extractors.CompWithSHA1Plus,
	"comp_with_sha256":    extractors.CompWithSHA256Plus,
	"sbom_signature":      extractors.SBOMSignature,

	"comp_with_dependencies":     extractors.CompWithDependencies,
	"sbom_completeness_declared": extractors.CompWithCompleteness,
	"primary_component":          extractors.SBOMWithPrimaryComponent,
	"comp_with_source_code":      extractors.CompWithSourceCode,
	"comp_with_supplier":         extractors.CompWithSupplier,
	"comp_with_purpose":          extractors.CompWithPackagePurpose,

	"comp_with_licenses":           extractors.CompWithLicenses,
	"comp_with_valid_licenses":     extractors.CompWithValidLicenses,
	"comp_with_declared_licenses":  extractors.CompWithDeclaredLicenses,
	"sbom_data_license":            extractors.SBOMDataLicense,
	"comp_no_deprecated_licenses":  extractors.CompWithDeprecatedLicenses,
	"comp_no_restrictive_licenses": extractors.CompWithRestrictiveLicenses,

	"comp_with_purl": extractors.CompWithPURL,
	"comp_with_cpe":  extractors.CompWithCPE,

	"sbom_spec_declared": extractors.SBOMWithSpec,
	"sbom_spec_version":  extractors.SBOMSpecVersion,
	"sbom_file_format":   extractors.SBOMFileFormat,
	"sbom_schema_valid":  extractors.SBOMSchemaValid,
}

// ComprFeatKey lists all comprehenssive categories features
// e.g. comp_with_name, comp_with_version, sbom_authors, etc
const (
	FCompWithName              catalog.ComprFeatKey = "comp_with_name"
	FCompWithVersion           catalog.ComprFeatKey = "comp_with_version"
	FCompWithIdentifiers       catalog.ComprFeatKey = "comp_with_identifiers"
	FSBOMCreationTimestamp     catalog.ComprFeatKey = "sbom_creation_timestamp"
	FSBOMAuthors               catalog.ComprFeatKey = "sbom_authors"
	FSBOMToolVersion           catalog.ComprFeatKey = "sbom_tool_version"
	FSBOMSupplier              catalog.ComprFeatKey = "sbom_supplier"
	FSBOMNamespace             catalog.ComprFeatKey = "sbom_namespace"
	FSBOMLifecycle             catalog.ComprFeatKey = "sbom_lifecycle"
	FCompWithChecksums         catalog.ComprFeatKey = "comp_with_checksums"
	FCompWithSHA256            catalog.ComprFeatKey = "comp_with_sha256"
	FSBOMSignature             catalog.ComprFeatKey = "sbom_signature"
	FCompWithDependencies      catalog.ComprFeatKey = "comp_with_dependencies"
	FSBOMCompletenessDeclared  catalog.ComprFeatKey = "sbom_completeness_declared"
	FPrimaryComponent          catalog.ComprFeatKey = "primary_component"
	FCompWithSourceCode        catalog.ComprFeatKey = "comp_with_source_code"
	FCompWithSupplier          catalog.ComprFeatKey = "comp_with_supplier"
	FCompWithPurpose           catalog.ComprFeatKey = "comp_with_purpose"
	FCompWithLicenses          catalog.ComprFeatKey = "comp_with_licenses"
	FCompWithValidLicenses     catalog.ComprFeatKey = "comp_with_valid_licenses"
	FCompWithDeclaredLicenses  catalog.ComprFeatKey = "comp_with_declared_licenses"
	FSBOMDataLicense           catalog.ComprFeatKey = "sbom_data_license"
	FCompNoDeprecatedLicenses  catalog.ComprFeatKey = "comp_no_deprecated_licenses"
	FCompNoRestrictiveLicenses catalog.ComprFeatKey = "comp_no_restrictive_licenses"
	FCompWithPURL              catalog.ComprFeatKey = "comp_with_purl"
	FCompWithCPE               catalog.ComprFeatKey = "comp_with_cpe"
	FSBOMSpecDeclared          catalog.ComprFeatKey = "sbom_spec_declared"
	FSBOMSpecVersion           catalog.ComprFeatKey = "sbom_spec_version"
	FSBOMFileFormat            catalog.ComprFeatKey = "sbom_file_format"
	FSBOMSchemaValid           catalog.ComprFeatKey = "sbom_schema_valid"
)

// ProfileKey lists all profiles
// e.g. ntia, bsi-v1.1, bsi-v2.0, oct, etc
const (
	ProfileNTIA  catalog.ProfileKey = "ntia"
	ProfileBSI11 catalog.ProfileKey = "bsi_v1_1"
	ProfileBSI20 catalog.ProfileKey = "bsi_v2_0"
	ProfileOCT   catalog.ProfileKey = "oct"
)

// ProFeatKey lists all profiles features
// e.g. comp_with_name, sbom_authors, etc
const (

	// common
	PFSBOMSpec              catalog.ProfFeatKey = "sbom_spec"
	PFSBOMDependencies      catalog.ProfFeatKey = "sbom_dependencies"
	PFSBOMAuthors           catalog.ProfFeatKey = "sbom_authors"
	PFSBOMCreationTimestamp catalog.ProfFeatKey = "sbom_creation_timestamp"
	PFCompName              catalog.ProfFeatKey = "comp_name"
	PFCompVersion           catalog.ProfFeatKey = "comp_version"

	// NTIA
	PFNTIACompName              catalog.ProfFeatKey = "comp_name"
	PFNTIACompVersion           catalog.ProfFeatKey = "comp_version"
	PFNTIACompSupplier          catalog.ProfFeatKey = "comp_supplier"
	PFNTIACompIdentifiers       catalog.ProfFeatKey = "comp_uniq_id"
	PFNTIASBOMAuthors           catalog.ProfFeatKey = "sbom_authors"
	PFNTIASBOMCreationTimestamp catalog.ProfFeatKey = "sbom_creation_timestamp"

	PFBSISBOMSpecVersion       catalog.ProfFeatKey = "sbom_spec_version"
	PFBSISBOMLifecycle         catalog.ProfFeatKey = "sbom_lifecycle"
	PFBSISBOMAuthors           catalog.ProfFeatKey = "sbom_authors"
	PFBSISBOMCreationTimestamp catalog.ProfFeatKey = "sbom_creation_timestamp"
	PFBSISBOMNamespace         catalog.ProfFeatKey = "sbom_namespace"
	PFBSICompName              catalog.ProfFeatKey = "comp_name"
	PFBSICompVersion           catalog.ProfFeatKey = "comp_version"
	PFBSICompLicense           catalog.ProfFeatKey = "comp_license"
	PFBSICompHash              catalog.ProfFeatKey = "comp_hash"
	PFBSICompSourceCodeURL     catalog.ProfFeatKey = "comp_source_code_url"
	PFBSICompDownloadURL       catalog.ProfFeatKey = "comp_download_code_url"
	PFBSICompSourceCodeHash    catalog.ProfFeatKey = "comp_source_code_hash"
	PFBSICompDependencies      catalog.ProfFeatKey = "comp_dependencies"

	PFBSI20SBOMSignature         catalog.ProfFeatKey = "sbom_signature"
	PFBSI20SBOMLinks             catalog.ProfFeatKey = "sbom_bomlinks"
	PFBSI20SBOMVulnerabilities   catalog.ProfFeatKey = "sbom_vulnerabilities"
	PFBSI20CompChecksumSHA256    catalog.ProfFeatKey = "comp_hash_256_sha"
	PFBSI20CompAssociatedLicense catalog.ProfFeatKey = "comp_associated_license"

	// PFOCTSBOMSpec catalog.ProfFeatKey = "oct_sbom_spec"
	PFOCTSBOMSpec             catalog.ProfFeatKey = "sbom_spec"
	PFOCTSBOMSpecVersion      catalog.ProfFeatKey = "sbom_spec_version"
	PFOCTCompName             catalog.ProfFeatKey = "comp_name"
	PFOCTCompVersion          catalog.ProfFeatKey = "comp_version"
	PFOCTSBOMNamespace        catalog.ProfFeatKey = "sbom_namespace"
	PFOCTSBOMDataLicense      catalog.ProfFeatKey = "sbom_license"
	PFOCTSBOMCreationTool     catalog.ProfFeatKey = "sbom_creation_tool"
	PFOCTSBOMSpdxID           catalog.ProfFeatKey = "sbom_spdxid"
	PFOCTSBOMName             catalog.ProfFeatKey = "sbom_name"
	PFOCTSBOMComment          catalog.ProfFeatKey = "sbom_comment"
	PFOCTSBOMOrg              catalog.ProfFeatKey = "sbom_organization"
	PFOCTCompSpdxID           catalog.ProfFeatKey = "comp_spdxid"
	PFOCTCompDownloadURL      catalog.ProfFeatKey = "comp_download_location"
	PFOCTCompFileAnalyzed     catalog.ProfFeatKey = "comp_file_analyze"
	PFOCTCompLicenseConcluded catalog.ProfFeatKey = "comp_license_concluded"
	PFOCTCompLicenseDeclared  catalog.ProfFeatKey = "comp_license_declared"
	PFOCTCompCopyright        catalog.ProfFeatKey = "comp_copyright"
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
	"BSI":                   ProfileBSI11,
	"bsi":                   ProfileBSI11,
	"BSI-V1.1":              ProfileBSI11,
	"bsi-v1.1":              ProfileBSI11,
	"bsi-v1_1":              ProfileBSI11,
	"BSI-V2.0":              ProfileBSI20,
	"bsi-v2.0":              ProfileBSI20,
	"bsi-v2_0":              ProfileBSI20,
	"OCT":                   ProfileOCT,
	"oct":                   ProfileOCT,
	"OpenChain-Telco":       ProfileOCT,
}

// Returns an error on serious IO / decode failures only.
func InitializeCatalog(conf config.Config) (*catalog.Catalog, error) {
	// 1) start from base catalog
	// baseProfiles := bindProfiles()
	// baseProfFeatures := bindProfFeatures()

	catal := &catalog.Catalog{}

	// cat := &catalog.Catalog{
	// 	ComprCategories: comprehenssiveCategories,
	// 	ComprFeatures:   comprehenssiveFeatures,
	// 	Profiles:        Profile,
	// 	ProfFeatures:    profilesFeatures,
	// 	// Order:           defaultOrder,
	// 	Aliases: catalog.Aliases{
	// 		Category: categoryAlias,
	// 		Profile:  profileAliases,
	// 		// Feature:  featureAlias(), // helper below; add if you maintain feature aliases
	// 	},
	// }

	// 2) if user supplied a config file, merge its entries (file overrides base)
	if strings.TrimSpace(conf.ConfigFile) != "" {

		categories, profiles, err := mergeConfigFileIntoCatalogYAML(conf.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", conf.ConfigFile, err)
		}

		if categories != nil {
			catal.ComprCategories = categories
		}
		if profiles != nil {
			catal.Profiles = profiles
		}

		return catal, nil
	}

	// 3) Apply runtime filters (profiles first — because profile selection impacts which profile features matter)
	if len(conf.Profile) > 0 {
		catal.Profiles = filterProfiles(conf.Profile)
		return catal, nil
	}

	// 5) Apply features filter (comprehensive features)
	if len(conf.Features) > 0 {
		return catal, nil
	}

	// 4) Apply categories filter (comprehensive scoring)
	if len(conf.Categories) > 0 {
		catal.ComprCategories = filterCategories(conf.Categories)
		return catal, nil
	}

	catal.ComprCategories = comprehenssiveCategories

	return catal, nil
}

// mergeConfigFileIntoCatalogYAML reads path and merges any found categories/profiles into out.
// It tries to detect which shape the file has by looking for top-level keys.
func mergeConfigFileIntoCatalogYAML(path string) ([]catalog.ComprCatSpec, []catalog.ProfSpec, error) {
	var cat []catalog.ComprCatSpec
	var prof []catalog.ProfSpec

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	lower := strings.ToLower(string(b))
	if strings.Contains(lower, "categories:") {
		fmt.Println("comprehenssive config file")
		cat, err = ReadComprConfigFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read comprehensive config: %w", err)
		}
		return cat, nil, nil
	}

	if strings.Contains(lower, "profiles:") {
		fmt.Println("profiles config file")
		prof, err = ReadProfileConfigFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read profile config: %w", err)
		}
		return nil, prof, nil
	}

	return cat, prof, nil
}

// filterCategories keeps only requested comprehensive categories.
func filterCategories(categories []string) []catalog.ComprCatSpec {
	var finalCats []catalog.ComprCatSpec
	for _, c := range categories {
		if c == "identification" {
			finalCats = append(finalCats, CatIdentificationSpec)
		}

		if c == "provenance" {
			finalCats = append(finalCats, CatProvenanceSpec)
		}

		if c == "integrity" {
			finalCats = append(finalCats, CatIntegritySpec)
		}

		if c == "completeness" {
			finalCats = append(finalCats, CatCompletenessSpec)
		}

		if c == "licensing" {
			finalCats = append(finalCats, CatLicensingAndComplianceSpec)
		}

		if c == "vulnerability" {
			finalCats = append(finalCats, CatVulnerabilityAndTraceSpec)
		}

		if c == "structural" {
			finalCats = append(finalCats, CatStructuralSpec)
		}
	}

	return finalCats
}

// filterProfiles keeps only requested profile keys (preserving order).
func filterProfiles(profiles []string) []catalog.ProfSpec {
	var finalProfiles []catalog.ProfSpec

	for _, profile := range profiles {
		if profile == "ntia" {
			finalProfiles = append(finalProfiles, profileNTIASpec)
		}
		if profile == "bsi-v1.1" {
			finalProfiles = append(finalProfiles, profileBSI11Spec)
		}
		if profile == "bsi-v2.0" {
			finalProfiles = append(finalProfiles, profileBSI20Spec)
		}
		if profile == "oct" {
			finalProfiles = append(finalProfiles, profileOCTSpec)
		}
	}
	return finalProfiles
}

var CatIdentificationSpec = catalog.ComprCatSpec{
	Key:         CatIdentification,
	Name:        "Identification",
	Weight:      10,
	Description: "Identification of components is critical for understanding supply chain metadata",
	Features: []catalog.ComprFeatSpec{
		{Key: FCompWithName, Description: "components with name", Weight: 0.40, Ignore: false, Evaluate: extractors.CompWithName},
		{Key: FCompWithVersion, Description: "components with version", Weight: 0.35, Ignore: false, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
		{Key: FCompWithIdentifiers, Description: "components with local identifiers", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithUniqLocalIDs},
	},
}

var CatProvenanceSpec = catalog.ComprCatSpec{
	Key:         CatProvenance,
	Name:        "Provenance",
	Description: "Enables trust and audit trails",
	Weight:      12,
	Features: []catalog.ComprFeatSpec{
		{Key: FSBOMCreationTimestamp, Description: "Document creation time", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTimestamp},
		{Key: FSBOMAuthors, Description: "Document authors", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMAuthors},
		{Key: FSBOMToolVersion, Description: "Document creator tool & version", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTool},
		{Key: FSBOMSupplier, Description: "Document supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMSupplier},
		{Key: FSBOMNamespace, Description: "Document URI/namespace", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMNamespace},
		{Key: FSBOMLifecycle, Description: "Document Lifecycle", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMLifeCycle},
	},
}

var CatIntegritySpec = catalog.ComprCatSpec{
	Key:         CatIntegrity,
	Name:        "Integrity",
	Description: "Allows for verification if artifacts were altered",
	Weight:      15,
	Features: []catalog.ComprFeatSpec{
		{Key: FCompWithChecksums, Description: "components with checksums", Weight: 0.60, Ignore: false, Evaluate: extractors.CompWithSHA1Plus},
		{Key: FCompWithSHA256, Description: "components with SHA-256+", Weight: 0.30, Ignore: false, Evaluate: extractors.CompWithSHA256Plus},
		{Key: FSBOMSignature, Description: "Document signature	", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMSignature},
	},
}

var CatCompletenessSpec = catalog.ComprCatSpec{
	Key:         CatCompleteness,
	Name:        "Completeness",
	Description: "Allows for vulnerability and impact analysis",
	Weight:      12,
	Features: []catalog.ComprFeatSpec{
		{Key: FCompWithDependencies, Description: "components with dependencies", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithDependencies},
		{Key: FSBOMCompletenessDeclared, Description: "components with declared completeness", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithCompleteness},
		{Key: FPrimaryComponent, Description: "Primary component identified", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMWithPrimaryComponent},
		{Key: FCompWithSourceCode, Description: "components with source code", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSourceCode},
		{Key: FCompWithSupplier, Description: "components with supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSupplier},
		{Key: FCompWithPurpose, Description: "components with primary purpose", Weight: 0.10, Ignore: false, Evaluate: extractors.CompWithPackagePurpose},
	},
}

var CatLicensingAndComplianceSpec = catalog.ComprCatSpec{
	Key:         CatLicensingAndCompliance,
	Name:        "Licensing",
	Description: "Determines redistribution rights and legal compliance",
	Weight:      15,
	Features: []catalog.ComprFeatSpec{
		{Key: FCompWithLicenses, Description: "components with licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithLicenses},
		{Key: FCompWithValidLicenses, Description: "components with valid licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithValidLicenses},
		{Key: FCompWithDeclaredLicenses, Description: "components with original licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeclaredLicenses},
		{Key: FSBOMDataLicense, Description: "Document data license", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMDataLicense},
		{Key: FCompNoDeprecatedLicenses, Description: "components without deprecated licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeprecatedLicenses},
		{Key: FCompNoRestrictiveLicenses, Description: "components without restrictive licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithRestrictiveLicenses},
	},
}

var CatVulnerabilityAndTraceSpec = catalog.ComprCatSpec{
	Key:         CatVulnerabilityAndTrace,
	Name:        "Vulnerability",
	Description: "Ability to map components to vulnerability databases",
	Weight:      10,
	Features: []catalog.ComprFeatSpec{
		{Key: FCompWithPURL, Description: "components with PURL", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithPURL},
		{Key: FCompWithCPE, Description: "components with CPE", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithCPE},
	},
}

var CatStructuralSpec = catalog.ComprCatSpec{
	Key:         CatStructural,
	Name:        "Structural",
	Description: "If a BOM can't be reliably parsed, all downstream automation fails",
	Weight:      8,
	Features: []catalog.ComprFeatSpec{
		{Key: FSBOMSpecDeclared, Description: "SBOM spec declared", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMWithSpec},
		{Key: FSBOMSpecVersion, Description: "SBOM spec version", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMSpecVersion},
		{Key: FSBOMFileFormat, Description: "SBOM file format", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMFileFormat},
		{Key: FSBOMSchemaValid, Description: "Schema validation", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMSchemaValid},
	},
}

var CatComponentQualityInfoSpec = catalog.ComprCatSpec{
	Key:         CatComponentQualityInfo,
	Name:        "Component Quality (Info)",
	Weight:      0,
	Description: "Real-time component risk assessment based on external threat intelligence. These metrics are informational only and do NOT affect the overall quality score",
	Features:    nil,
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

// bindComprFeatures maps ComprFeatKey with ComprFeatSpec
// spec contains key, weight, evaluating function
var comprehenssiveFeatures = []catalog.ComprFeatSpec{
	// Identification
	{Key: FCompWithName, Description: "components with name", Weight: 0.40, Ignore: false, Evaluate: extractors.CompWithName},
	{Key: FCompWithVersion, Description: "components with version", Weight: 0.35, Ignore: false, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
	{Key: FCompWithIdentifiers, Description: "components with local identifiers", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithUniqLocalIDs},

	// Provenance
	{Key: FSBOMCreationTimestamp, Description: "Document creation time", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTimestamp},
	{Key: FSBOMAuthors, Description: "Document authors", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMAuthors},
	{Key: FSBOMToolVersion, Description: "Document creator tool & version", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTool},
	{Key: FSBOMSupplier, Description: "Document supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMSupplier},
	{Key: FSBOMNamespace, Description: "Document URI/namespace", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMNamespace},
	{Key: FSBOMLifecycle, Description: "Document Lifecycle", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMLifeCycle},

	// Integrity
	{Key: FCompWithChecksums, Description: "components with checksums", Weight: 0.60, Ignore: false, Evaluate: extractors.CompWithSHA1Plus},
	{Key: FCompWithSHA256, Description: "components with SHA-256+", Weight: 0.30, Ignore: false, Evaluate: extractors.CompWithSHA256Plus},
	{Key: FSBOMSignature, Description: "Document signature	", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMSignature},

	// Completeness
	{Key: FCompWithDependencies, Description: "components with dependencies", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithDependencies},
	{Key: FSBOMCompletenessDeclared, Description: "components with declared completeness", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithCompleteness},
	{Key: FPrimaryComponent, Description: "Primary component identified", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMWithPrimaryComponent},
	{Key: FCompWithSourceCode, Description: "components with source code", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSourceCode},
	{Key: FCompWithSupplier, Description: "components with supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSupplier},
	{Key: FCompWithPurpose, Description: "components with primary purpose", Weight: 0.10, Ignore: false, Evaluate: extractors.CompWithPackagePurpose},

	// Licensing & Compliance
	{Key: FCompWithLicenses, Description: "components with licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithLicenses},
	{Key: FCompWithValidLicenses, Description: "components with valid licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithValidLicenses},
	{Key: FCompWithDeclaredLicenses, Description: "components with original licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeclaredLicenses},
	{Key: FSBOMDataLicense, Description: "Document data license", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMDataLicense},
	{Key: FCompNoDeprecatedLicenses, Description: "components without deprecated licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeprecatedLicenses},
	{Key: FCompNoRestrictiveLicenses, Description: "components without restrictive licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithRestrictiveLicenses},

	// Vulnerability & Traceability
	{Key: FCompWithPURL, Description: "components with PURL", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithPURL},
	{Key: FCompWithCPE, Description: "components with CPE", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithCPE},

	// Structural
	{Key: FSBOMSpecDeclared, Description: "SBOM spec declared", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMWithSpec},
	{Key: FSBOMSpecVersion, Description: "SBOM spec version", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMSpecVersion},
	{Key: FSBOMFileFormat, Description: "SBOM file format", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMFileFormat},
	{Key: FSBOMSchemaValid, Description: "Schema validation", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMSchemaValid},
}

// bindProfFeatures profileFeatureKey with profileFeatureSpec
// spec contains key, required, description, evaluation function
var profilesFeatures = []catalog.ProfFeatSpec{
	// common
	{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
	{Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SBOMDepedencies},
	{Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SBOMAuthors},
	{Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
	{Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.CompName},
	{Key: PFCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.CompVersion},

	// NTIA
	{Key: PFNTIACompSupplier, Required: true, Description: "Supplier/manufacturer info", Evaluate: profiles.CompWithSupplier},
	{Key: PFNTIACompIdentifiers, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqID},

	{Key: PFBSISBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.BSISBOMSpecVersion},
	{Key: PFBSISBOMLifecycle, Required: true, Description: "SBOM Lifecycle", Evaluate: profiles.BSISBOMBuildLifecycle},
	{Key: PFBSISBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},
	{Key: PFBSICompLicense, Required: true, Description: "License info", Evaluate: profiles.BSICompWithLicenses},
	{Key: PFBSICompHash, Required: true, Description: "Checksums present", Evaluate: profiles.BSICompWithHash},
	{Key: PFBSICompSourceCodeURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeURI},
	{Key: PFBSICompDownloadURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithDownloadURI},
	{Key: PFBSICompSourceCodeHash, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeHash},
	{Key: PFBSICompDependencies, Required: true, Description: "Dependency mapping present", Evaluate: profiles.BSICompWithDependency},

	{Key: PFBSI20SBOMSignature, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithSignature},
	{Key: PFBSI20SBOMLinks, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithBomLinks},
	{Key: PFBSI20SBOMVulnerabilities, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithVulnerabilities},
	{Key: PFBSI20CompChecksumSHA256, Required: true, Description: "Digital signature", Evaluate: profiles.CompSHA256Plus},
	{Key: PFBSI20CompAssociatedLicense, Required: true, Description: "Digital signature", Evaluate: profiles.BSICompWithAssociatedLicenses},

	// OCT
	{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.OCTSBOMSpec},
	{Key: PFOCTSBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.OCTSBOMSpecVersion},
	{Key: PFOCTCompName, Required: true, Description: "All components have names", Evaluate: profiles.OCTCompWithName},
	{Key: PFOCTCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.OCTCompWithVersion},
	{Key: PFOCTSBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.OCTSBOMNamespace},
	{Key: PFOCTCompLicenseDeclared, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithDeclaredLicense},
	{Key: PFOCTCompLicenseConcluded, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithConcludedLicense},

	{Key: PFOCTSBOMDataLicense, Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: profiles.OCTSBOMDataLicense},
	{Key: PFOCTSBOMCreationTool, Required: true, Description: "Creator tool + version", Evaluate: profiles.OCTSBOMToolCreation},
	{Key: PFOCTSBOMSpdxID, Required: true, Description: "Document SPDXID", Evaluate: profiles.OCTSBOMSpdxID},
	{Key: PFOCTSBOMName, Required: true, Description: "SBOM name", Evaluate: profiles.OCTSBOMName},
	{Key: PFOCTSBOMComment, Required: false, Description: "Additional info", Evaluate: profiles.OCTSBOMComment},
	{Key: PFOCTSBOMOrg, Required: true, Description: "Organization info", Evaluate: profiles.OCTSBOMCreationOrganization},
	{Key: PFOCTCompSpdxID, Required: true, Description: "Unique SPDX IDs", Evaluate: profiles.OCTCompWithSpdxID},
	{Key: PFOCTCompFileAnalyzed, Required: false, Description: "File analysis status", Evaluate: profiles.OCTCompWithFileAnalyzed},
	{Key: PFOCTCompCopyright, Required: true, Description: "Copyright text", Evaluate: profiles.OCTCompWithCopyright},
}

var profileNTIASpec = catalog.ProfSpec{
	Key:         ProfileNTIA,
	Name:        "ntia",
	Description: "NTIA Minimum Elements",
	Features: []catalog.ProfFeatSpec{
		{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
		{Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.CompName},
		{Key: PFNTIACompIdentifiers, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqID},
		{Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SBOMDepedencies},
		{Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SBOMAuthors},
		{Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
	},
}

var profileBSI11Spec = catalog.ProfSpec{
	Key:         ProfileBSI11,
	Name:        "bsi-v1.1",
	Description: "BSI TR-03183-2 v1.1",
	Features: []catalog.ProfFeatSpec{
		{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
		{Key: PFBSISBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.BSISBOMSpecVersion},
		{Key: PFBSISBOMLifecycle, Required: true, Description: "SBOM Lifecycle", Evaluate: profiles.BSISBOMBuildLifecycle},
		{Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SBOMDepedencies},
		{Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SBOMAuthors},
		{Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
		{Key: PFBSISBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},

		{Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.CompName},
		{Key: PFCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.CompVersion},

		{Key: PFBSICompLicense, Required: true, Description: "License info", Evaluate: profiles.BSICompWithLicenses},
		{Key: PFBSICompHash, Required: true, Description: "Checksums present", Evaluate: profiles.BSICompWithHash},
		{Key: PFBSICompSourceCodeURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeURI},
		{Key: PFBSICompDownloadURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithDownloadURI},
		{Key: PFBSICompSourceCodeHash, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeHash},
		{Key: PFBSICompDependencies, Required: true, Description: "Dependency mapping present", Evaluate: profiles.BSICompWithDependency},
	},
}

var profileBSI20Spec = catalog.ProfSpec{
	Key:         ProfileBSI20,
	Name:        "bsi-v2.0",
	Description: "BSI TR-03183-2 v2.0",
	Features: []catalog.ProfFeatSpec{
		{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
		{Key: PFBSISBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.BSISBOMSpecVersion},
		{Key: PFBSISBOMLifecycle, Required: true, Description: "SBOM Lifecycle", Evaluate: profiles.BSISBOMBuildLifecycle},
		{Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SBOMDepedencies},
		{Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SBOMAuthors},
		{Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
		{Key: PFBSISBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},

		{Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.CompName},
		{Key: PFCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.CompVersion},

		{Key: PFBSICompLicense, Required: true, Description: "License info", Evaluate: profiles.BSICompWithLicenses},
		{Key: PFBSICompHash, Required: true, Description: "Checksums present", Evaluate: profiles.BSICompWithHash},
		{Key: PFBSICompSourceCodeURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeURI},
		{Key: PFBSICompDownloadURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithDownloadURI},
		{Key: PFBSICompSourceCodeHash, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeHash},
		{Key: PFBSICompDependencies, Required: true, Description: "Dependency mapping present", Evaluate: profiles.BSICompWithDependency},

		{Key: PFBSI20SBOMSignature, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithSignature},
		{Key: PFBSI20SBOMLinks, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithBomLinks},
		{Key: PFBSI20SBOMVulnerabilities, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithVulnerabilities},
		{Key: PFBSI20CompChecksumSHA256, Required: true, Description: "Digital signature", Evaluate: profiles.CompSHA256Plus},
		{Key: PFBSI20CompAssociatedLicense, Required: true, Description: "Digital signature", Evaluate: profiles.BSICompWithAssociatedLicenses},
	},
}

var profileOCTSpec = catalog.ProfSpec{
	Key:         ProfileOCT,
	Name:        "oct",
	Description: "OpenChain Telco (OCT)",
	Features: []catalog.ProfFeatSpec{
		{Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.OCTSBOMSpec},
		{Key: PFOCTSBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.OCTSBOMSpecVersion},
		{Key: PFOCTCompName, Required: true, Description: "All components have names", Evaluate: profiles.OCTCompWithName},
		{Key: PFOCTCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.OCTCompWithVersion},
		{Key: PFOCTSBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.OCTSBOMNamespace},
		{Key: PFOCTCompLicenseDeclared, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithDeclaredLicense},
		{Key: PFOCTCompLicenseConcluded, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithConcludedLicense},

		{Key: PFOCTSBOMDataLicense, Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: profiles.OCTSBOMDataLicense},
		{Key: PFOCTSBOMCreationTool, Required: true, Description: "Creator tool + version", Evaluate: profiles.OCTSBOMToolCreation},
		{Key: PFOCTSBOMSpdxID, Required: true, Description: "Document SPDXID", Evaluate: profiles.OCTSBOMSpdxID},
		{Key: PFOCTSBOMName, Required: true, Description: "SBOM name", Evaluate: profiles.OCTSBOMName},
		{Key: PFOCTSBOMComment, Required: false, Description: "Additional info", Evaluate: profiles.OCTSBOMComment},
		{Key: PFOCTSBOMOrg, Required: true, Description: "Organization info", Evaluate: profiles.OCTSBOMCreationOrganization},
		{Key: PFOCTCompSpdxID, Required: true, Description: "Unique SPDX IDs", Evaluate: profiles.OCTCompWithSpdxID},
		{Key: PFOCTCompFileAnalyzed, Required: false, Description: "File analysis status", Evaluate: profiles.OCTCompWithFileAnalyzed},
		{Key: PFOCTCompCopyright, Required: true, Description: "Copyright text", Evaluate: profiles.OCTCompWithCopyright},
	},
}

var Profile = []catalog.ProfSpec{
	profileNTIASpec,
	profileBSI11Spec,
	profileBSI20Spec,
	profileOCTSpec,
}
