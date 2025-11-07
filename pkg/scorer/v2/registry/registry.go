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

func InitializeCatalog() *catalog.Catalog {
	comprCategories, order := bindComprCategories()
	comprFeatures := bindComprFeatures()

	profiles := bindProfiles()
	profFeatures := bindProfFeatures()

	aliases := catalog.Aliases{
		Category: categoryAlias,
		Profile:  profileAliases,
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

var CatIdentificationSpec = catalog.ComprCatSpec{
	Key:         CatIdentification,
	Name:        "Identification",
	Weight:      10,
	Description: "Identification of components is critical for understanding supply chain metadata",
	Features: []catalog.ComprFeatKey{
		FCompWithName,
		FCompWithVersion,
		FCompWithIdentifiers,
	},
}

var CatProvenanceSpec = catalog.ComprCatSpec{
	Key:         CatProvenance,
	Name:        "Provenance",
	Description: "Enables trust and audit trails",
	Weight:      12,
	Features: []catalog.ComprFeatKey{
		FSBOMCreationTimestamp,
		FSBOMAuthors,
		FSBOMToolVersion,
		FSBOMSupplier,
		FSBOMNamespace,
		FSBOMLifecycle,
	},
}

var CatIntegritySpec = catalog.ComprCatSpec{
	Key:         CatIntegrity,
	Name:        "Integrity",
	Description: "Allows for verification if artifacts were altered",
	Weight:      15,
	Features: []catalog.ComprFeatKey{
		FCompWithChecksums,
		FCompWithSHA256,
		FSBOMSignature,
	},
}

var CatCompletenessSpec = catalog.ComprCatSpec{
	Key:         CatCompleteness,
	Name:        "Completeness",
	Description: "Allows for vulnerability and impact analysis",
	Weight:      12,
	Features: []catalog.ComprFeatKey{
		FCompWithDependencies,
		FSBOMCompletenessDeclared,
		FPrimaryComponent,
		FCompWithSourceCode,
		FCompWithSupplier,
		FCompWithPurpose,
	},
}

var CatLicensingAndComplianceSpec = catalog.ComprCatSpec{
	Key:         CatLicensingAndCompliance,
	Name:        "Licensing",
	Description: "Determines redistribution rights and legal compliance",
	Weight:      15,
	Features: []catalog.ComprFeatKey{
		FCompWithLicenses,
		FCompWithValidLicenses,
		FCompWithDeclaredLicenses,
		FSBOMDataLicense,
		FCompNoDeprecatedLicenses,
		FCompNoRestrictiveLicenses,
	},
}

var CatVulnerabilityAndTraceSpec = catalog.ComprCatSpec{
	Key:         CatVulnerabilityAndTrace,
	Name:        "Vulnerability",
	Description: "Ability to map components to vulnerability databases",
	Weight:      10,
	Features: []catalog.ComprFeatKey{
		FCompWithPURL,
		FCompWithCPE,
	},
}

var CatStructuralSpec = catalog.ComprCatSpec{
	Key:         CatStructural,
	Name:        "Structural",
	Description: "If a BOM can't be reliably parsed, all downstream automation fails",
	Weight:      8,
	Features: []catalog.ComprFeatKey{
		FSBOMSpecDeclared,
		FSBOMSpecVersion,
		FSBOMFileFormat,
		FSBOMSchemaValid,
	},
}

var CatComponentQualityInfoSpec = catalog.ComprCatSpec{
	Key:         CatComponentQualityInfo,
	Name:        "Component Quality (Info)",
	Weight:      0,
	Description: "Real-time component risk assessment based on external threat intelligence. These metrics are informational only and do NOT affect the overall quality score",
	Features:    nil,
}

// bindComprCategories maps ComprCatKey with ComprCatSpec
// spec contains key, name, weight, features
func bindComprCategories() (map[catalog.ComprCatKey]catalog.ComprCatSpec, []catalog.ComprCatKey) {
	cats := map[catalog.ComprCatKey]catalog.ComprCatSpec{
		// Identification Category
		CatIdentification: CatIdentificationSpec,

		// Provenance Category
		CatProvenance: CatProvenanceSpec,

		// Integrity Category
		CatIntegrity: CatIntegritySpec,

		// Completeness Category
		CatCompleteness: CatCompletenessSpec,

		// LicensingAndCompliance Category
		CatLicensingAndCompliance: CatLicensingAndComplianceSpec,

		// Vulnerability Category
		CatVulnerabilityAndTrace: CatVulnerabilityAndTraceSpec,

		// Structural Category
		CatStructural: CatStructuralSpec,

		// ComponentQualityInfo Category
		CatComponentQualityInfo: CatComponentQualityInfoSpec,
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

// bindComprFeatures maps ComprFeatKey with ComprFeatSpec
// spec contains key, weight, evaluating function
func bindComprFeatures() map[catalog.ComprFeatKey]catalog.ComprFeatSpec {
	return map[catalog.ComprFeatKey]catalog.ComprFeatSpec{
		// Identification
		FCompWithName:        {Key: FCompWithName, Description: "components with name", Weight: 0.40, Ignore: false, Evaluate: extractors.CompWithName},
		FCompWithVersion:     {Key: FCompWithVersion, Description: "components with version", Weight: 0.35, Ignore: false, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
		FCompWithIdentifiers: {Key: FCompWithIdentifiers, Description: "components with local identifiers", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithUniqLocalIDs},

		// Provenance
		FSBOMCreationTimestamp: {Key: FSBOMCreationTimestamp, Description: "Document creation time", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTimestamp},
		FSBOMAuthors:           {Key: FSBOMAuthors, Description: "Document authors", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMAuthors},
		FSBOMToolVersion:       {Key: FSBOMToolVersion, Description: "Document creator tool & version", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMCreationTool},
		FSBOMSupplier:          {Key: FSBOMSupplier, Description: "Document supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMSupplier},
		FSBOMNamespace:         {Key: FSBOMNamespace, Description: "Document URI/namespace", Weight: 0.15, Ignore: false, Evaluate: extractors.SBOMNamespace},
		FSBOMLifecycle:         {Key: FSBOMLifecycle, Description: "Document Lifecycle", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMLifeCycle},

		// Integrity
		FCompWithChecksums: {Key: FCompWithChecksums, Description: "components with checksums", Weight: 0.60, Ignore: false, Evaluate: extractors.CompWithSHA1Plus},
		FCompWithSHA256:    {Key: FCompWithSHA256, Description: "components with SHA-256+", Weight: 0.30, Ignore: false, Evaluate: extractors.CompWithSHA256Plus},
		FSBOMSignature:     {Key: FSBOMSignature, Description: "Document signature	", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMSignature},

		// Completeness
		FCompWithDependencies:     {Key: FCompWithDependencies, Description: "components with dependencies", Weight: 0.25, Ignore: false, Evaluate: extractors.CompWithDependencies},
		FSBOMCompletenessDeclared: {Key: FSBOMCompletenessDeclared, Description: "components with declared completeness", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithCompleteness},
		FPrimaryComponent:         {Key: FPrimaryComponent, Description: "Primary component identified", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMWithPrimaryComponent},
		FCompWithSourceCode:       {Key: FCompWithSourceCode, Description: "components with source code", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSourceCode},
		FCompWithSupplier:         {Key: FCompWithSupplier, Description: "components with supplier", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithSupplier},
		FCompWithPurpose:          {Key: FCompWithPurpose, Description: "components with primary purpose", Weight: 0.10, Ignore: false, Evaluate: extractors.CompWithPackagePurpose},

		// Licensing & Compliance
		FCompWithLicenses:          {Key: FCompWithLicenses, Description: "components with licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithLicenses},
		FCompWithValidLicenses:     {Key: FCompWithValidLicenses, Description: "components with valid licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithValidLicenses},
		FCompWithDeclaredLicenses:  {Key: FCompWithDeclaredLicenses, Description: "components with original licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeclaredLicenses},
		FSBOMDataLicense:           {Key: FSBOMDataLicense, Description: "Document data license", Weight: 0.10, Ignore: false, Evaluate: extractors.SBOMDataLicense},
		FCompNoDeprecatedLicenses:  {Key: FCompNoDeprecatedLicenses, Description: "components without deprecated licenses", Weight: 0.15, Ignore: false, Evaluate: extractors.CompWithDeprecatedLicenses},
		FCompNoRestrictiveLicenses: {Key: FCompNoRestrictiveLicenses, Description: "components without restrictive licenses", Weight: 0.20, Ignore: false, Evaluate: extractors.CompWithRestrictiveLicenses},

		// Vulnerability & Traceability
		FCompWithPURL: {Key: FCompWithPURL, Description: "components with PURL", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithPURL},
		FCompWithCPE:  {Key: FCompWithCPE, Description: "components with CPE", Weight: 0.50, Ignore: false, Evaluate: extractors.CompWithCPE},

		// Structural
		FSBOMSpecDeclared: {Key: FSBOMSpecDeclared, Description: "SBOM spec declared", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMWithSpec},
		FSBOMSpecVersion:  {Key: FSBOMSpecVersion, Description: "SBOM spec version", Weight: 0.30, Ignore: false, Evaluate: extractors.SBOMSpecVersion},
		FSBOMFileFormat:   {Key: FSBOMFileFormat, Description: "SBOM file format", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMFileFormat},
		FSBOMSchemaValid:  {Key: FSBOMSchemaValid, Description: "Schema validation", Weight: 0.20, Ignore: false, Evaluate: extractors.SBOMSchemaValid},
	}
}

// bindProfFeatures profileFeatureKey with profileFeatureSpec
// spec contains key, required, description, evaluation function
func bindProfFeatures() map[catalog.ProfFeatKey]catalog.ProfFeatSpec {
	return map[catalog.ProfFeatKey]catalog.ProfFeatSpec{
		// common
		PFSBOMSpec:              {Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SBOMAutomationSpec},
		PFSBOMDependencies:      {Key: PFSBOMDependencies, Required: true, Description: "Primary Comp With Dependenies", Evaluate: profiles.SBOMDepedencies},
		PFSBOMAuthors:           {Key: PFSBOMAuthors, Required: true, Description: "Author/creator info", Evaluate: profiles.SBOMAuthors},
		PFSBOMCreationTimestamp: {Key: PFSBOMCreationTimestamp, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SBOMCreationTimestamp},
		PFCompName:              {Key: PFCompName, Required: true, Description: "All components have names", Evaluate: profiles.CompName},
		PFCompVersion:           {Key: PFCompVersion, Required: true, Description: "Components have versions", Evaluate: profiles.CompVersion},

		// NTIA
		PFNTIACompSupplier:    {Key: PFNTIACompSupplier, Required: true, Description: "Supplier/manufacturer info", Evaluate: profiles.CompWithSupplier},
		PFNTIACompIdentifiers: {Key: PFNTIACompIdentifiers, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqID},

		PFBSISBOMSpecVersion:    {Key: PFBSISBOMSpecVersion, Required: true, Description: "Supported spec version declared", Evaluate: profiles.BSISBOMSpecVersion},
		PFBSISBOMLifecycle:      {Key: PFBSISBOMLifecycle, Required: true, Description: "SBOM Lifecycle", Evaluate: profiles.BSISBOMBuildLifecycle},
		PFBSISBOMNamespace:      {Key: PFBSISBOMNamespace, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.BSISBOMNamespace},
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

var profileNTIASpec = catalog.ProfSpec{
	Key:         ProfileNTIA,
	Name:        "ntia",
	Description: "NTIA Minimum Elements",
	Features: []catalog.ProfFeatKey{
		PFSBOMSpec,
		PFNTIACompName,
		PFNTIACompVersion,
		PFNTIACompIdentifiers,
		PFSBOMDependencies,
		PFNTIASBOMAuthors,
		PFNTIASBOMCreationTimestamp,
	},
}

var profileBSI11Spec = catalog.ProfSpec{
	Key:         ProfileBSI11,
	Name:        "bsi-v1.1",
	Description: "BSI TR-03183-2 v1.1",
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
}

var profileBSI20Spec = catalog.ProfSpec{
	Key:         ProfileBSI20,
	Name:        "bsi-v2.0",
	Description: "BSI TR-03183-2 v2.0",
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
}

var profileOCTSpec = catalog.ProfSpec{
	Key:         ProfileOCT,
	Name:        "oct",
	Description: "OpenChain Telco (OCT)",
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
}

// bindProfiles maps profile key with profile spec
// spec contains key, name, and features
// ProfileNTIA with it's spec
// ProfileBSI11 with it's spec
// ProfileBSI20 with it's spec
func bindProfiles() map[catalog.ProfileKey]catalog.ProfSpec {
	return map[catalog.ProfileKey]catalog.ProfSpec{
		ProfileNTIA:  profileNTIASpec,
		ProfileBSI11: profileBSI11Spec,
		ProfileBSI20: profileBSI20Spec,
		ProfileOCT:   profileOCTSpec,
	}
}
