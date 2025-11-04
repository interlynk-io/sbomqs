package registry

import (
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
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

type (
	PFNTIAFeatKey    catalog.ProfFeatKey
	PFBSIV1_1FeatKey catalog.ProfFeatKey
	PFBSIV2_0FeatKey catalog.ProfFeatKey
	PFOCTFeatKey     catalog.ProfFeatKey
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
	// PFNTIASBOMSpec              catalog.ProfFeatKey = "sbom_spec"
	PFNTIACompName        catalog.ProfFeatKey = "comp_name"
	PFNTIACompVersion     catalog.ProfFeatKey = "comp_version"
	PFNTIACompSupplier    catalog.ProfFeatKey = "comp_supplier"
	PFNTIACompIdentifiers catalog.ProfFeatKey = "comp_uniq_id"
	// PFNTIASBOMDependencies      catalog.ProfFeatKey = "sbom_dependencies"
	PFNTIASBOMAuthors           catalog.ProfFeatKey = "sbom_authors"
	PFNTIASBOMCreationTimestamp catalog.ProfFeatKey = "sbom_creation_timestamp"

	// PFBSISBOMSpec              catalog.ProfFeatKey = "sbom_spec"
	PFBSISBOMSpecVersion catalog.ProfFeatKey = "sbom_spec_version"
	PFBSISBOMLifecycle   catalog.ProfFeatKey = "sbom_lifecycle"
	// PFBSISBOMDependencies      catalog.ProfFeatKey = "sbom_dependencies"
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

	PFOCTSBOMSpec             catalog.ProfFeatKey = "oct_sbom_spec"
	PFOCTSBOMSpecVersion      catalog.ProfFeatKey = "oct_sbom_spec_version"
	PFOCTCompName             catalog.ProfFeatKey = "oct_comp_name"
	PFOCTCompVersion          catalog.ProfFeatKey = "oct_comp_version"
	PFOCTSBOMNamespace        catalog.ProfFeatKey = "oct_sbom_namespace"
	PFOCTSBOMDataLicense      catalog.ProfFeatKey = "oct_sbom_license"
	PFOCTSBOMCreationTool     catalog.ProfFeatKey = "oct_sbom_creation_tool"
	PFOCTSBOMSpdxID           catalog.ProfFeatKey = "oct_sbom_spdxid"
	PFOCTSBOMName             catalog.ProfFeatKey = "oct_sbom_name"
	PFOCTSBOMComment          catalog.ProfFeatKey = "oct_sbom_comment"
	PFOCTSBOMOrg              catalog.ProfFeatKey = "oct_sbom_organization"
	PFOCTCompSpdxID           catalog.ProfFeatKey = "oct_comp_spdxid"
	PFOCTCompDownloadURL      catalog.ProfFeatKey = "oct_comp_download_location"
	PFOCTCompFileAnalyzed     catalog.ProfFeatKey = "oct_comp_file_analyze"
	PFOCTCompLicenseConcluded catalog.ProfFeatKey = "oct_comp_license_concluded"
	PFOCTCompLicenseDeclared  catalog.ProfFeatKey = "oct_comp_license_declared"
	PFOCTCompCopyright        catalog.ProfFeatKey = "oct_comp_copyright"
)

func InitializeCatalog() *catalog.Catalog {
	comprFeatures := bindComprFeatures()
	comprCategories, order := bindComprCategories()
	profiles := bindProfiles()
	profFeatures := bindProfFeatures()

	aliases := catalog.Aliases{
		Category: map[string]catalog.ComprCatKey{
			"identification":                 CatIdentification,
			"provenance":                     CatProvenance,
			"integrity":                      CatIntegrity,
			"completeness":                   CatCompleteness,
			"licensing":                      CatLicensingAndCompliance,
			"licensingandcompliance":         CatLicensingAndCompliance, // tolerate old camel
			"licensing_and_compliance":       CatLicensingAndCompliance,
			"vulnerability":                  CatVulnerabilityAndTrace,
			"vulnerabilityandtraceability":   CatVulnerabilityAndTrace,
			"vulnerability_and_traceability": CatVulnerabilityAndTrace,
			"structural":                     CatStructural,
			"componentquality(info)":         CatComponentQualityInfo,
			"component_quality_info":         CatComponentQualityInfo,
		},
		Feature: map[string]catalog.ComprFeatKey{
			// identification
			"comp_with_name":        FCompWithName,
			"comp_with_version":     FCompWithVersion,
			"comp_with_identifiers": FCompWithIdentifiers,
			"comp_with_ids":         FCompWithIdentifiers, // legacy alias

			// provenance
			"sbom_creation_timestamp": FSBOMCreationTimestamp,
			"sbom_authors":            FSBOMAuthors,
			"sbom_tool_version":       FSBOMToolVersion,
			"sbom_supplier":           FSBOMSupplier,
			"sbom_namespace":          FSBOMNamespace,
			"sbom_lifecycle":          FSBOMLifecycle,

			// integrity
			"comp_with_checksums": FCompWithChecksums,
			"comp_with_sha256":    FCompWithSHA256,
			"sbom_signature":      FSBOMSignature,

			// completeness
			"comp_with_dependencies":     FCompWithDependencies,
			"sbom_completeness_declared": FSBOMCompletenessDeclared,
			"primary_component":          FPrimaryComponent,
			"comp_with_source_code":      FCompWithSourceCode,
			"comp_with_supplier":         FCompWithSupplier,
			"comp_with_purpose":          FCompWithPurpose,

			// licensing
			"comp_with_licenses":           FCompWithLicenses,
			"comp_with_valid_licenses":     FCompWithValidLicenses,
			"comp_with_declared_licenses":  FCompWithDeclaredLicenses,
			"sbom_data_license":            FSBOMDataLicense,
			"comp_no_deprecated_licenses":  FCompNoDeprecatedLicenses,
			"comp_no_restrictive_licenses": FCompNoRestrictiveLicenses,

			// vuln/trace
			"comp_with_purl": FCompWithPURL,
			"compwithpurl":   FCompWithPURL, // casing alias
			"comp_with_cpe":  FCompWithCPE,
			"compwithcpe":    FCompWithCPE,

			// structural
			"sbom_spec_declared": FSBOMSpecDeclared,
			"sbomwithspec":       FSBOMSpecDeclared, // legacy alias
			"sbom_spec_version":  FSBOMSpecVersion,
			"sbomspecversion":    FSBOMSpecVersion,
			"sbom_file_format":   FSBOMFileFormat,
			"sbomfileformat":     FSBOMFileFormat,
			"sbom_schema_valid":  FSBOMSchemaValid,
			"sbomschemavalid":    FSBOMSchemaValid,
		},
		Profile: map[string]catalog.ProfileKey{
			"ntia":                  ProfileNTIA,
			"nita-minimum-elements": ProfileNTIA,
			"NTIA-minimum-elements": ProfileNTIA,
			"NTIA-Minimum-Elements": ProfileNTIA,
			"NTIA":                  ProfileNTIA,
			"BSI-V1.1":              ProfileBSI11,
			"bsi-v1.1":              ProfileBSI11,
			"bsi-v1_1":              ProfileBSI11,
			"BSI-V2.0":              ProfileBSI20,
			"bsi-v2.0":              ProfileBSI20,
			"bsi-v2_0":              ProfileBSI20,
			"OCT":                   ProfileOCT,
			"oct":                   ProfileOCT,
			"OpenChain-Telco":       ProfileOCT,
		},
	}

	return &catalog.Catalog{
		ComprFeatures:   comprFeatures,
		ComprCategories: comprCategories,
		Profiles:        profiles,
		ProfFeatures:    profFeatures,
		Order:           order,
		Aliases:         aliases,
	}
}

func bindComprCategories() (map[catalog.ComprCatKey]catalog.ComprCatSpec, []catalog.ComprCatKey) {
	cats := map[catalog.ComprCatKey]catalog.ComprCatSpec{
		// Identification Category
		CatIdentification: {
			Key:    CatIdentification,
			Name:   "Identification",
			Weight: 10,
			Features: []catalog.ComprFeatKey{
				FCompWithName,
				FCompWithVersion,
				FCompWithIdentifiers,
			},
		},

		// Provenance Category
		CatProvenance: {
			Key:    CatProvenance,
			Name:   "Provenance",
			Weight: 12,
			Features: []catalog.ComprFeatKey{
				FSBOMCreationTimestamp,
				FSBOMAuthors,
				FSBOMToolVersion,
				FSBOMSupplier,
				FSBOMNamespace,
				FSBOMLifecycle,
			},
		},

		// Integrity Category
		CatIntegrity: {
			Key:    CatIntegrity,
			Name:   "Integrity",
			Weight: 15,
			Features: []catalog.ComprFeatKey{
				FCompWithChecksums,
				FCompWithSHA256,
				FSBOMSignature,
			},
		},

		// Completeness Category
		CatCompleteness: {
			Key:    CatCompleteness,
			Name:   "Completeness",
			Weight: 12,
			Features: []catalog.ComprFeatKey{
				FCompWithDependencies,
				FSBOMCompletenessDeclared,
				FPrimaryComponent,
				FCompWithSourceCode,
				FCompWithSupplier,
				FCompWithPurpose,
			},
		},

		// LicensingAndCompliance Category
		CatLicensingAndCompliance: {
			Key:    CatLicensingAndCompliance,
			Name:   "Licensing",
			Weight: 15,
			Features: []catalog.ComprFeatKey{
				FCompWithLicenses,
				FCompWithValidLicenses,
				FCompWithDeclaredLicenses,
				FSBOMDataLicense,
				FCompNoDeprecatedLicenses,
				FCompNoRestrictiveLicenses,
			},
		},

		// Vulnerability Category
		CatVulnerabilityAndTrace: {
			Key:    CatVulnerabilityAndTrace,
			Name:   "Vulnerability",
			Weight: 10,
			Features: []catalog.ComprFeatKey{
				FCompWithPURL,
				FCompWithCPE,
			},
		},

		// Structural Category
		CatStructural: {
			Key:    CatStructural,
			Name:   "Structural",
			Weight: 8,
			Features: []catalog.ComprFeatKey{
				FSBOMSpecDeclared,
				FSBOMSpecVersion,
				FSBOMFileFormat,
				FSBOMSchemaValid,
			},
		},

		// ComponentQualityInfo Category
		CatComponentQualityInfo: {
			Key:      CatComponentQualityInfo,
			Name:     "Component Quality (Info)",
			Weight:   0,
			Features: nil,
		},
	}

	// Default evaluation order
	order := []catalog.ComprCatKey{
		CatIdentification,
		CatProvenance,
		CatIntegrity,
		CatCompleteness,
		CatLicensingAndCompliance,
		CatVulnerabilityAndTrace,
		CatStructural,
		CatComponentQualityInfo,
	}

	return cats, order
}

func bindComprFeatures() map[catalog.ComprFeatKey]catalog.ComprFeatSpec {
	return map[catalog.ComprFeatKey]catalog.ComprFeatSpec{
		// Identification
		FCompWithName:        {Key: FCompWithName, Weight: 0.40, Evaluate: extractors.CompWithName},
		FCompWithVersion:     {Key: FCompWithVersion, Weight: 0.35, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
		FCompWithIdentifiers: {Key: FCompWithIdentifiers, Weight: 0.25, Evaluate: extractors.CompWithUniqLocalIDs},

		// Provenance
		FSBOMCreationTimestamp: {Key: FSBOMCreationTimestamp, Weight: 0.20, Evaluate: extractors.SBOMCreationTimestamp},
		FSBOMAuthors:           {Key: FSBOMAuthors, Weight: 0.20, Evaluate: extractors.SBOMAuthors},
		FSBOMToolVersion:       {Key: FSBOMToolVersion, Weight: 0.20, Evaluate: extractors.SBOMCreationTool},
		FSBOMSupplier:          {Key: FSBOMSupplier, Weight: 0.15, Evaluate: extractors.SBOMSupplier},
		FSBOMNamespace:         {Key: FSBOMNamespace, Weight: 0.15, Evaluate: extractors.SBOMNamespace},
		FSBOMLifecycle:         {Key: FSBOMLifecycle, Weight: 0.10, Evaluate: extractors.SBOMLifeCycle},

		// Integrity
		FSBOMSignature:     {Key: FSBOMSignature, Weight: 0.10, Evaluate: extractors.SBOMSignature},
		FCompWithChecksums: {Key: FCompWithChecksums, Weight: 0.60, Evaluate: extractors.CompWithSHA1Plus},
		FCompWithSHA256:    {Key: FCompWithSHA256, Weight: 0.30, Evaluate: extractors.CompWithSHA256Plus},

		// Completeness
		FCompWithDependencies:     {Key: FCompWithDependencies, Weight: 0.25, Evaluate: extractors.CompWithDependencies},
		FSBOMCompletenessDeclared: {Key: FSBOMCompletenessDeclared, Weight: 0.15, Evaluate: extractors.CompWithCompleteness},
		FPrimaryComponent:         {Key: FPrimaryComponent, Weight: 0.20, Evaluate: extractors.SBOMWithPrimaryComponent},
		FCompWithSourceCode:       {Key: FCompWithSourceCode, Weight: 0.15, Evaluate: extractors.CompWithSourceCode},
		FCompWithSupplier:         {Key: FCompWithSupplier, Weight: 0.15, Evaluate: extractors.CompWithSupplier},
		FCompWithPurpose:          {Key: FCompWithPurpose, Weight: 0.10, Evaluate: extractors.CompWithPackagePurpose},

		// Licensing & Compliance
		FCompWithLicenses:          {Key: FCompWithLicenses, Weight: 0.20, Evaluate: extractors.CompWithLicenses},
		FCompWithValidLicenses:     {Key: FCompWithValidLicenses, Weight: 0.20, Evaluate: extractors.CompWithValidLicenses},
		FCompWithDeclaredLicenses:  {Key: FCompWithDeclaredLicenses, Weight: 0.15, Evaluate: extractors.CompWithDeclaredLicenses},
		FSBOMDataLicense:           {Key: FSBOMDataLicense, Weight: 0.10, Evaluate: extractors.SBOMDataLicense},
		FCompNoDeprecatedLicenses:  {Key: FCompNoDeprecatedLicenses, Weight: 0.15, Evaluate: extractors.CompWithDeprecatedLicenses},
		FCompNoRestrictiveLicenses: {Key: FCompNoRestrictiveLicenses, Weight: 0.20, Evaluate: extractors.CompWithRestrictiveLicenses},

		// Vulnerability & Traceability
		FCompWithPURL: {Key: FCompWithPURL, Weight: 0.50, Evaluate: extractors.CompWithPURL},
		FCompWithCPE:  {Key: FCompWithCPE, Weight: 0.50, Evaluate: extractors.CompWithCPE},

		// Structural
		FSBOMSpecDeclared: {Key: FSBOMSpecDeclared, Weight: 0.30, Evaluate: extractors.SBOMWithSpec},
		FSBOMSpecVersion:  {Key: FSBOMSpecVersion, Weight: 0.30, Evaluate: extractors.SBOMSpecVersion},
		FSBOMFileFormat:   {Key: FSBOMFileFormat, Weight: 0.20, Evaluate: extractors.SBOMFileFormat},
		FSBOMSchemaValid:  {Key: FSBOMSchemaValid, Weight: 0.20, Evaluate: extractors.SBOMSchemaValid},
	}
}

func bindProfFeatures() map[catalog.ProfFeatKey]catalog.ProfFeatSpec {
	return map[catalog.ProfFeatKey]catalog.ProfFeatSpec{
		// common
		PFSBOMSpec:              {Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
		PFSBOMDependencies:      {Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SbomWithDepedencies},
		PFSBOMAuthors:           {Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.BSISBOMWithAuthors},
		PFSBOMCreationTimestamp: {Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.BSISBOMWithTimeStamp},
		PFCompName:              {Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.BSICompWithName},
		PFCompVersion:           {Key: PFCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.BSICompWithVersion},

		// NTIA
		// PFNTIACompName:        {Key: PFNTIACompName, Required: true, Description: "Component Name", Evaluate: profiles.CompWithName},
		// PFNTIACompVersion:     {Key: PFNTIACompVersion, Required: true, Description: "Components version", Evaluate: profiles.CompWithVersion},
		PFNTIACompSupplier:    {Key: PFNTIACompSupplier, Required: true, Description: "Supplier/manufacturer info", Evaluate: profiles.CompWithSupplier},
		PFNTIACompIdentifiers: {Key: PFNTIACompIdentifiers, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqID},
		// PFNTIASBOMDependencies:      {Key: PFNTIASBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SbomWithDepedencies},
		// PFNTIASBOMAuthors:           {Key: PFNTIASBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SbomWithAuthors},
		// PFNTIASBOMCreationTimestamp: {Key: PFNTIASBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SbomWithTimeStamp},

		// PFSBOMSpec:                 {Key: PFSBOMSpec, Required: true, Description: "SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.BSISBOMSpec},
		PFBSISBOMSpecVersion: {Key: PFBSISBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.BSISBOMSpecVersion},
		PFBSISBOMLifecycle:   {Key: PFBSISBOMLifecycle, Required: true, Description: "SBOM Lifecycle", Evaluate: profiles.BSISBOMBuildLifecycle},
		// PFBSISBOMDependencies:      {Key: PFBSISBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.BSISBOMWithDepedencies},
		// PFBSISBOMAuthors:           {Key: PFBSISBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.BSISBOMWithAuthors},
		// PFBSISBOMCreationTimestamp: {Key: PFBSISBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.BSISBOMWithTimeStamp},
		PFBSISBOMNamespace: {Key: PFBSISBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},
		// PFBSICompName:           {Key: PFBSICompName, Required: true, Description: "All components have names", Evaluate: profiles.BSICompWithName},
		// PFBSICompVersion:        {Key: PFBSICompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.BSICompWithVersion},
		PFBSICompLicense:        {Key: PFBSICompLicense, Required: true, Description: "License info", Evaluate: profiles.BSICompWithLicenses},
		PFBSICompHash:           {Key: PFBSICompHash, Required: true, Description: "Checksums present", Evaluate: profiles.BSICompWithHash},
		PFBSICompSourceCodeURL:  {Key: PFBSICompSourceCodeURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeURI},
		PFBSICompDownloadURL:    {Key: PFBSICompDownloadURL, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithDownloadURI},
		PFBSICompSourceCodeHash: {Key: PFBSICompSourceCodeHash, Required: true, Description: "Source/VCS references", Evaluate: profiles.BSICompWithSourceCodeHash},
		PFBSICompDependencies:   {Key: PFBSICompDependencies, Required: true, Description: "Dependency mapping present", Evaluate: profiles.BSICompWithDependency},

		PFBSI20SBOMSignature:         {Key: PFBSI20SBOMSignature, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithSignature},
		PFBSI20SBOMLinks:             {Key: PFBSI20SBOMLinks, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithBomLinks},
		PFBSI20SBOMVulnerabilities:   {Key: PFBSI20SBOMVulnerabilities, Required: true, Description: "Digital signature", Evaluate: profiles.BSISBOMWithVulnerabilities},
		PFBSI20CompChecksumSHA256:    {Key: PFBSI20CompChecksumSHA256, Required: true, Description: "Digital signature", Evaluate: profiles.CompSHA256Plus},
		PFBSI20CompAssociatedLicense: {Key: PFBSI20CompAssociatedLicense, Required: true, Description: "Digital signature", Evaluate: profiles.BSICompWithAssociatedLicenses},

		// OCT
		PFOCTSBOMSpec:             {Key: PFOCTSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.OCTSBOMSpec},
		PFOCTSBOMSpecVersion:      {Key: PFOCTSBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.OCTSBOMSpecVersion},
		PFOCTCompName:             {Key: PFOCTCompName, Required: true, Description: "All components have names", Evaluate: profiles.OCTCompWithName},
		PFOCTCompVersion:          {Key: PFOCTCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.OCTCompWithVersion},
		PFOCTSBOMNamespace:        {Key: PFOCTSBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.OCTSBOMNamespace},
		PFOCTCompLicenseDeclared:  {Key: PFOCTCompLicenseDeclared, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithDeclaredLicense},
		PFOCTCompLicenseConcluded: {Key: PFOCTCompLicenseConcluded, Required: true, Description: "License info", Evaluate: profiles.OCTCompWithConcludedLicense},

		PFOCTSBOMDataLicense:  {Key: PFOCTSBOMDataLicense, Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: profiles.OCTSBOMDataLicense},
		PFOCTSBOMCreationTool: {Key: PFOCTSBOMCreationTool, Required: true, Description: "Creator tool + version", Evaluate: profiles.OCTSBOMToolCreation},
		PFOCTSBOMSpdxID:       {Key: PFOCTSBOMSpdxID, Required: true, Description: "Document SPDXID", Evaluate: profiles.OCTSBOMSpdxID},
		PFOCTSBOMName:         {Key: PFOCTSBOMName, Required: true, Description: "SBOM name", Evaluate: profiles.OCTSBOMName},
		PFOCTSBOMComment:      {Key: PFOCTSBOMComment, Required: false, Description: "Additional info", Evaluate: profiles.OCTSBOMComment},
		PFOCTSBOMOrg:          {Key: PFOCTSBOMOrg, Required: true, Description: "Organization info", Evaluate: profiles.OCTSBOMCreationOrganization},
		PFOCTCompSpdxID:       {Key: PFOCTCompSpdxID, Required: true, Description: "Unique SPDX IDs", Evaluate: profiles.OCTCompWithSpdxID},
		PFOCTCompFileAnalyzed: {Key: PFOCTCompFileAnalyzed, Required: false, Description: "File analysis status", Evaluate: profiles.OCTCompWithFileAnalyzed},
		PFOCTCompCopyright:    {Key: PFOCTCompCopyright, Required: true, Description: "Copyright text", Evaluate: profiles.OCTCompWithCopyright},
	}
}

func bindProfiles() map[catalog.ProfileKey]catalog.ProfSpec {
	return map[catalog.ProfileKey]catalog.ProfSpec{
		ProfileNTIA: {
			Key:  ProfileNTIA,
			Name: "NTIA Minimum Elements",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFNTIACompName,
				PFNTIACompVersion,
				PFNTIACompIdentifiers,
				PFSBOMDependencies,
				PFNTIASBOMAuthors,
				PFNTIASBOMCreationTimestamp,
			},
		},

		ProfileBSI11: {
			Key:  ProfileBSI11,
			Name: "BSI TR-03183-2 v1.1",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFBSISBOMSpecVersion,
				PFBSISBOMLifecycle,
				PFSBOMDependencies,
				PFBSISBOMAuthors,
				PFBSISBOMCreationTimestamp,
				PFBSISBOMNamespace,

				PFCompName,
				PFCompVersion,
				PFBSICompLicense,
				PFBSICompHash,
				PFBSICompSourceCodeURL,
				PFBSICompDownloadURL,
				PFBSICompSourceCodeHash,
				PFBSICompDependencies,
			},
		},

		ProfileBSI20: {
			Key:  ProfileBSI20,
			Name: "BSI TR-03183-2 v2.0",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFBSISBOMSpecVersion,
				PFBSISBOMLifecycle,
				PFSBOMDependencies,
				PFBSISBOMAuthors,
				PFBSISBOMCreationTimestamp,
				PFBSISBOMNamespace,

				PFCompName,
				PFCompVersion,
				PFBSICompLicense,
				PFBSICompHash,
				PFBSICompSourceCodeURL,
				PFBSICompDownloadURL,
				PFBSICompSourceCodeHash,
				PFBSICompDependencies,

				PFBSI20SBOMSignature,
				PFBSI20SBOMLinks,
				PFBSI20SBOMVulnerabilities,
				PFBSI20CompChecksumSHA256,
				PFBSI20CompAssociatedLicense,
			},
		},

		ProfileOCT: {
			Key:  ProfileOCT,
			Name: "OpenChain Telco (OCT)",
			Features: []catalog.ProfFeatKey{
				PFOCTSBOMSpec,
				PFOCTSBOMSpecVersion,
				PFOCTSBOMSpdxID,
				PFOCTSBOMName,
				PFOCTSBOMComment,
				PFOCTSBOMOrg,
				PFOCTSBOMCreationTool,
				PFOCTSBOMNamespace,
				PFOCTSBOMDataLicense,

				PFOCTCompName,
				PFOCTCompVersion,
				PFOCTCompSpdxID,
				PFOCTCompDownloadURL,
				PFOCTCompFileAnalyzed,
				PFOCTCompLicenseConcluded,
				PFOCTCompLicenseDeclared,
				PFOCTCompCopyright,
			},
		},
	}
}
