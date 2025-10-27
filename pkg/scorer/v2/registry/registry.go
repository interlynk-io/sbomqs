package registry

import (
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/extractors"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
)

// type (
// 	// comprehenssive cateogy and it's features keys
// 	ComprCatKey  string
// 	ComprFeatKey string

// 	// profiles and it's feature keys
// 	ProfileKey  string
// 	ProfFeatKey string
// )

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

// ProFeatKey lists all profiles features
// e.g. comp_with_name, sbom_authors, etc
const (
	PFSBOMSpec                catalog.ProfFeatKey = "sbom_with_spec"
	PFSBOMSpecVersion         catalog.ProfFeatKey = "sbom_spec_version"
	PFSBOMSpecFileFormat      catalog.ProfFeatKey = "sbom_file_format"
	PFCompWithName            catalog.ProfFeatKey = "comp_with_name"
	PFCompName                catalog.ProfFeatKey = "comp_with_name"
	PFCompVersion             catalog.ProfFeatKey = "comp_with_version"
	PFCompIdentifiers         catalog.ProfFeatKey = "comp_with_identifiers"
	PFCompSupplier            catalog.ProfFeatKey = "comp_with_supplier"
	PFCompDependencies        catalog.ProfFeatKey = "comp_with_dependencies"
	PFSBOMCreationTimestamp   catalog.ProfFeatKey = "sbom_creation_timestamp"
	PFSBOMAuthors             catalog.ProfFeatKey = "sbom_authors"
	PFSBOMNamespace           catalog.ProfFeatKey = "sbom_namespace"
	PFCompLicense             catalog.ProfFeatKey = "comp_with_licenses"
	PFCompChecksum            catalog.ProfFeatKey = "comp_with_checksums"
	PFCompSourceCode          catalog.ProfFeatKey = "comp_with_source_code"
	PFSBOMSchema              catalog.ProfFeatKey = "sbom_schema_valid"
	PFCompChecksumSHA256      catalog.ProfFeatKey = "comp_with_checksum_sha256"
	PFSBOMSignature           catalog.ProfFeatKey = "sbom_signature"
	PFCompValidLicense        catalog.ProfFeatKey = "comp_with_valid_licenses"
	PFSBOMDataLicense         catalog.ProfFeatKey = "sbom_data_license"
	PFCompPURLID              catalog.ProfFeatKey = "comp_with_purl"
	PFCompCPEID               catalog.ProfFeatKey = "comp_with_cpe"
	PFSBOMCreationToolVersion catalog.ProfFeatKey = "sbom_tool_version"
	PFCompDeclaredLicense     catalog.ProfFeatKey = "comp_with_declared_licenses"
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
				FSBOMSignature,
				FCompWithChecksums,
				FCompWithSHA256,
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
			Name:   "Licensing & Compliance",
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
			Name:   "Vulnerability & Traceability",
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
		PFSBOMSpec:                {Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SbomWithVersionCompliant},
		PFSBOMSpecVersion:         {Key: PFSBOMSpec, Required: true, Description: "Supported spec version declared", Evaluate: profiles.SbomWithVersionCompliant},
		PFSBOMSpecFileFormat:      {Key: PFSBOMSpec, Required: true, Description: "Supported file format", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompName:                {Key: PFSBOMSpec, Required: true, Description: "All components have names", Evaluate: profiles.CompWithNameCheck},
		PFCompVersion:             {Key: PFSBOMSpec, Required: true, Description: "Components have versions", Evaluate: profiles.CompWithVersionCheck},
		PFCompIdentifiers:         {Key: PFSBOMSpec, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqIDCheck},
		PFCompSupplier:            {Key: PFSBOMSpec, Required: true, Description: "Supplier/manufacturer info", Evaluate: profiles.CompWithSupplierCheck},
		PFCompDependencies:        {Key: PFSBOMSpec, Required: true, Description: "Dependency mapping present", Evaluate: profiles.CompWithDependencyCheck},
		PFSBOMCreationTimestamp:   {Key: PFSBOMSpec, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SbomWithTimeStampCheck},
		PFSBOMAuthors:             {Key: PFSBOMSpec, Required: true, Description: "Author/creator info", Evaluate: profiles.SbomWithAuthorsCheck},
		PFSBOMNamespace:           {Key: PFSBOMSpec, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompLicense:             {Key: PFSBOMSpec, Required: true, Description: "License info", Evaluate: profiles.CompWithLicensesCheck},
		PFCompChecksum:            {Key: PFSBOMSpec, Required: true, Description: "Checksums present", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompSourceCode:          {Key: PFSBOMSpec, Required: true, Description: "Source/VCS references", Evaluate: profiles.SbomWithVersionCompliant},
		PFSBOMSchema:              {Key: PFSBOMSpec, Required: true, Evaluate: profiles.SbomWithVersionCompliant},
		PFCompChecksumSHA256:      {Key: PFSBOMSpec, Required: true, Description: "SHA-256 or stronger", Evaluate: profiles.CompWithSHA256ChecksumsCheck},
		PFSBOMSignature:           {Key: PFSBOMSpec, Required: true, Description: "Digital signature", Evaluate: profiles.SbomWithSignatureCheck},
		PFCompValidLicense:        {Key: PFSBOMSpec, Required: true, Description: "Valid SPDX license IDs", Evaluate: profiles.SbomWithVersionCompliant},
		PFSBOMDataLicense:         {Key: PFSBOMSpec, Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompPURLID:              {Key: PFSBOMSpec, Required: true, Description: "PURLs", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompCPEID:               {Key: PFSBOMSpec, Required: true, Description: "CPEs", Evaluate: profiles.SbomWithVersionCompliant},
		PFSBOMCreationToolVersion: {Key: PFSBOMSpec, Required: true, Description: "Creator tool + version", Evaluate: profiles.SbomWithVersionCompliant},
		PFCompDeclaredLicense:     {Key: PFSBOMSpec, Required: true, Description: "Declared/original license", Evaluate: profiles.CompWithDeclaredLicensesCheck},
	}
}

func bindProfiles() map[catalog.ProfileKey]catalog.ProfSpec {
	return map[catalog.ProfileKey]catalog.ProfSpec{
		ProfileNTIA: {
			Key:  ProfileNTIA,
			Name: "NTIA Minimum Elements",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFSBOMSpecVersion,
				PFSBOMSpecFileFormat,
				PFCompName,
				PFCompVersion,
				PFCompIdentifiers,
				PFCompSupplier,
				PFCompDependencies,
				PFSBOMCreationTimestamp,
				PFSBOMAuthors,
			},
		},

		ProfileBSI11: {
			Key:  ProfileBSI11,
			Name: "BSI TR-03183-2 v1.1",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFSBOMSpecVersion,
				PFSBOMCreationTimestamp,
				PFSBOMAuthors,
				PFSBOMNamespace,
				PFCompName,
				PFCompVersion,
				PFCompLicense,
				PFCompChecksum,
				PFCompDependencies,
				PFCompSourceCode,
				PFCompSupplier,
			},
		},

		ProfileBSI20: {
			Key:  ProfileBSI20,
			Name: "BSI TR-03183-2 v2.0",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFSBOMSpecVersion,
				PFSBOMCreationTimestamp,
				PFSBOMAuthors,
				PFSBOMSpecFileFormat,
				PFSBOMSchema,
				PFCompChecksum,
				PFCompChecksumSHA256,
				PFSBOMSignature,
				PFCompValidLicense,
				PFSBOMDataLicense,
				PFCompName,
				PFCompVersion,
				PFCompIdentifiers,
				PFCompPURLID,
				PFCompCPEID,
				PFCompDependencies,
			},
		},

		ProfileOCT: {
			Key:  ProfileOCT,
			Name: "OpenChain Telco (OCT)",
			Features: []catalog.ProfFeatKey{
				PFSBOMSpec,
				PFSBOMSpecVersion,
				PFSBOMNamespace,
				PFSBOMDataLicense,
				PFSBOMCreationToolVersion,
				PFCompName,
				PFCompVersion,
				PFCompIdentifiers,
				PFCompLicense,
				PFCompDeclaredLicense,
				PFCompChecksum,
				PFCompSourceCode,
				PFCompSupplier,
				PFCompDependencies,
			},
		},
	}
}
