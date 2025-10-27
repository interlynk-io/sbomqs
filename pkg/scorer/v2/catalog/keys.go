// package catalog

// import (
// 	"github.com/interlynk-io/sbomqs/pkg/sbom"
// 	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/extractors"
// 	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
// )

// type (
// 	// comprehenssive cateogy and it's features keys
// 	ComprCatKey  string
// 	ComprFeatKey string

// 	// profiles and it's feature keys
// 	ProfileKey  string
// 	ProfFeatKey string
// )

// // ComprCatKey lists all comprehenssive catefories
// // e.g. identification, provenance, integrity, etc
// const (
// 	CatIdentification         ComprCatKey = "identification"
// 	CatProvenance             ComprCatKey = "provenance"
// 	CatIntegrity              ComprCatKey = "integrity"
// 	CatCompleteness           ComprCatKey = "completeness"
// 	CatLicensingAndCompliance ComprCatKey = "licensing_and_compliance"
// 	CatVulnerabilityAndTrace  ComprCatKey = "vulnerability_and_traceability"
// 	CatStructural             ComprCatKey = "structural"
// 	CatComponentQualityInfo   ComprCatKey = "component_quality_info" // weight 0
// )

// // ComprFeatKey lists all comprehenssive categories features
// // e.g. comp_with_name, comp_with_version, sbom_authors, etc
// const (
// 	FCompWithName              ComprFeatKey = "comp_with_name"
// 	FCompWithVersion           ComprFeatKey = "comp_with_version"
// 	FCompWithIdentifiers       ComprFeatKey = "comp_with_identifiers"
// 	FSBOMCreationTimestamp     ComprFeatKey = "sbom_creation_timestamp"
// 	FSBOMAuthors               ComprFeatKey = "sbom_authors"
// 	FSBOMToolVersion           ComprFeatKey = "sbom_tool_version"
// 	FSBOMSupplier              ComprFeatKey = "sbom_supplier"
// 	FSBOMNamespace             ComprFeatKey = "sbom_namespace"
// 	FSBOMLifecycle             ComprFeatKey = "sbom_lifecycle"
// 	FCompWithChecksums         ComprFeatKey = "comp_with_checksums"
// 	FCompWithSHA256            ComprFeatKey = "comp_with_sha256"
// 	FSBOMSignature             ComprFeatKey = "sbom_signature"
// 	FCompWithDependencies      ComprFeatKey = "comp_with_dependencies"
// 	FSBOMCompletenessDeclared  ComprFeatKey = "sbom_completeness_declared"
// 	FPrimaryComponent          ComprFeatKey = "primary_component"
// 	FCompWithSourceCode        ComprFeatKey = "comp_with_source_code"
// 	FCompWithSupplier          ComprFeatKey = "comp_with_supplier"
// 	FCompWithPurpose           ComprFeatKey = "comp_with_purpose"
// 	FCompWithLicenses          ComprFeatKey = "comp_with_licenses"
// 	FCompWithValidLicenses     ComprFeatKey = "comp_with_valid_licenses"
// 	FCompWithDeclaredLicenses  ComprFeatKey = "comp_with_declared_licenses"
// 	FSBOMDataLicense           ComprFeatKey = "sbom_data_license"
// 	FCompNoDeprecatedLicenses  ComprFeatKey = "comp_no_deprecated_licenses"
// 	FCompNoRestrictiveLicenses ComprFeatKey = "comp_no_restrictive_licenses"
// 	FCompWithPURL              ComprFeatKey = "comp_with_purl"
// 	FCompWithCPE               ComprFeatKey = "comp_with_cpe"
// 	FSBOMSpecDeclared          ComprFeatKey = "sbom_spec_declared"
// 	FSBOMSpecVersion           ComprFeatKey = "sbom_spec_version"
// 	FSBOMFileFormat            ComprFeatKey = "sbom_file_format"
// 	FSBOMSchemaValid           ComprFeatKey = "sbom_schema_valid"
// )

// // ProfileKey lists all profiles
// // e.g. ntia, bsi-v1.1, bsi-v2.0, oct, etc
// const (
// 	ProfileNTIA  ProfileKey = "ntia"
// 	ProfileBSI11 ProfileKey = "bsi_v1_1"
// 	ProfileBSI20 ProfileKey = "bsi_v2_0"
// 	ProfileOCT   ProfileKey = "oct"
// )

// // ProFeatKey lists all profiles features
// // e.g. comp_with_name, sbom_authors, etc
// const (
// 	PFSBOMSpec                ProfFeatKey = "sbom_with_spec"
// 	PFSBOMSpecVersion         ProfFeatKey = "sbom_spec_version"
// 	PFSBOMSpecFileFormat      ProfFeatKey = "sbom_file_format"
// 	PFCompWithName            ProfFeatKey = "comp_with_name"
// 	PFCompName                ProfFeatKey = "comp_with_name"
// 	PFCompVersion             ProfFeatKey = "comp_with_version"
// 	PFCompIdentifiers         ProfFeatKey = "comp_with_identifiers"
// 	PFCompSupplier            ProfFeatKey = "comp_with_supplier"
// 	PFCompDependencies        ProfFeatKey = "comp_with_dependencies"
// 	PFSBOMCreationTimestamp   ProfFeatKey = "sbom_creation_timestamp"
// 	PFSBOMAuthors             ProfFeatKey = "sbom_authors"
// 	PFSBOMNamespace           ProfFeatKey = "sbom_namespace"
// 	PFCompLicense             ProfFeatKey = "comp_with_licenses"
// 	PFCompChecksum            ProfFeatKey = "comp_with_checksums"
// 	PFCompSourceCode          ProfFeatKey = "comp_with_source_code"
// 	PFSBOMSchema              ProfFeatKey = "sbom_schema_valid"
// 	PFCompChecksumSHA256      ProfFeatKey = "comp_with_checksum_sha256"
// 	PFSBOMSignature           ProfFeatKey = "sbom_signature"
// 	PFCompValidLicense        ProfFeatKey = "comp_with_valid_licenses"
// 	PFSBOMDataLicense         ProfFeatKey = "sbom_data_license"
// 	PFCompPURLID              ProfFeatKey = "comp_with_purl"
// 	PFCompCPEID               ProfFeatKey = "comp_with_cpe"
// 	PFSBOMCreationToolVersion ProfFeatKey = "sbom_tool_version"
// 	PFCompDeclaredLicense     ProfFeatKey = "comp_with_declared_licenses"
// )

// func InitializeCatalog(doc sbom.Document) *Catalog {
// 	comprFeatures := bindComprFeatures(doc)
// 	comprCategories, order := bindComprCategories()
// 	profiles := bindProfiles()
// 	profFeatures := bindProfFeatures(doc)

// 	aliases := Aliases{
// 		Category: map[string]ComprCatKey{
// 			"identification":                 CatIdentification,
// 			"provenance":                     CatProvenance,
// 			"integrity":                      CatIntegrity,
// 			"completeness":                   CatCompleteness,
// 			"licensing":                      CatLicensingAndCompliance,
// 			"licensingandcompliance":         CatLicensingAndCompliance, // tolerate old camel
// 			"licensing_and_compliance":       CatLicensingAndCompliance,
// 			"vulnerability":                  CatVulnerabilityAndTrace,
// 			"vulnerabilityandtraceability":   CatVulnerabilityAndTrace,
// 			"vulnerability_and_traceability": CatVulnerabilityAndTrace,
// 			"structural":                     CatStructural,
// 			"componentquality(info)":         CatComponentQualityInfo,
// 			"component_quality_info":         CatComponentQualityInfo,
// 		},
// 		Feature: map[string]ComprFeatKey{
// 			// identification
// 			"comp_with_name":        FCompWithName,
// 			"comp_with_version":     FCompWithVersion,
// 			"comp_with_identifiers": FCompWithIdentifiers,
// 			"comp_with_ids":         FCompWithIdentifiers, // legacy alias

// 			// provenance
// 			"sbom_creation_timestamp": FSBOMCreationTimestamp,
// 			"sbom_authors":            FSBOMAuthors,
// 			"sbom_tool_version":       FSBOMToolVersion,
// 			"sbom_supplier":           FSBOMSupplier,
// 			"sbom_namespace":          FSBOMNamespace,
// 			"sbom_lifecycle":          FSBOMLifecycle,

// 			// integrity
// 			"comp_with_checksums": FCompWithChecksums,
// 			"comp_with_sha256":    FCompWithSHA256,
// 			"sbom_signature":      FSBOMSignature,

// 			// completeness
// 			"comp_with_dependencies":     FCompWithDependencies,
// 			"sbom_completeness_declared": FSBOMCompletenessDeclared,
// 			"primary_component":          FPrimaryComponent,
// 			"comp_with_source_code":      FCompWithSourceCode,
// 			"comp_with_supplier":         FCompWithSupplier,
// 			"comp_with_purpose":          FCompWithPurpose,

// 			// licensing
// 			"comp_with_licenses":           FCompWithLicenses,
// 			"comp_with_valid_licenses":     FCompWithValidLicenses,
// 			"comp_with_declared_licenses":  FCompWithDeclaredLicenses,
// 			"sbom_data_license":            FSBOMDataLicense,
// 			"comp_no_deprecated_licenses":  FCompNoDeprecatedLicenses,
// 			"comp_no_restrictive_licenses": FCompNoRestrictiveLicenses,

// 			// vuln/trace
// 			"comp_with_purl": FCompWithPURL,
// 			"compwithpurl":   FCompWithPURL, // casing alias
// 			"comp_with_cpe":  FCompWithCPE,
// 			"compwithcpe":    FCompWithCPE,

// 			// structural
// 			"sbom_spec_declared": FSBOMSpecDeclared,
// 			"sbomwithspec":       FSBOMSpecDeclared, // legacy alias
// 			"sbom_spec_version":  FSBOMSpecVersion,
// 			"sbomspecversion":    FSBOMSpecVersion,
// 			"sbom_file_format":   FSBOMFileFormat,
// 			"sbomfileformat":     FSBOMFileFormat,
// 			"sbom_schema_valid":  FSBOMSchemaValid,
// 			"sbomschemavalid":    FSBOMSchemaValid,
// 		},
// 		Profile: map[string]ProfileKey{
// 			"ntia":                  ProfileNTIA,
// 			"nita-minimum-elements": ProfileNTIA,
// 			"NTIA-minimum-elements": ProfileNTIA,
// 			"NTIA-Minimum-Elements": ProfileNTIA,
// 			"NTIA":                  ProfileNTIA,
// 			"BSI-V1.1":              ProfileBSI11,
// 			"bsi-v1.1":              ProfileBSI11,
// 			"bsi-v1_1":              ProfileBSI11,
// 			"BSI-V2.0":              ProfileBSI20,
// 			"bsi-v2.0":              ProfileBSI20,
// 			"bsi-v2_0":              ProfileBSI20,
// 			"OCT":                   ProfileOCT,
// 			"oct":                   ProfileOCT,
// 			"OpenChain-Telco":       ProfileOCT,
// 		},
// 	}

// 	return &Catalog{
// 		ComprFeatures:   comprFeatures,
// 		ComprCategories: comprCategories,
// 		Profiles:        profiles,
// 		ProfFeatures:    profFeatures,
// 		Order:           order,
// 		Aliases:         aliases,
// 	}
// }

// func bindComprCategories() (map[ComprCatKey]ComprCatSpec, []ComprCatKey) {
// 	cats := map[ComprCatKey]ComprCatSpec{
// 		// Identification Category
// 		CatIdentification: {
// 			Key:    CatIdentification,
// 			Name:   "Identification",
// 			Weight: 10,
// 			Features: []ComprFeatKey{
// 				FCompWithName,
// 				FCompWithVersion,
// 				FCompWithIdentifiers,
// 			},
// 		},

// 		// Provenance Category
// 		CatProvenance: {
// 			Key:    CatProvenance,
// 			Name:   "Provenance",
// 			Weight: 12,
// 			Features: []ComprFeatKey{
// 				FSBOMCreationTimestamp,
// 				FSBOMAuthors,
// 				FSBOMToolVersion,
// 				FSBOMSupplier,
// 				FSBOMNamespace,
// 				FSBOMLifecycle,
// 			},
// 		},

// 		// Integrity Category
// 		CatIntegrity: {
// 			Key:    CatIntegrity,
// 			Name:   "Integrity",
// 			Weight: 15,
// 			Features: []ComprFeatKey{
// 				FSBOMSignature,
// 				FCompWithChecksums,
// 				FCompWithSHA256,
// 			},
// 		},

// 		// Completeness Category
// 		CatCompleteness: {
// 			Key:    CatCompleteness,
// 			Name:   "Completeness",
// 			Weight: 12,
// 			Features: []ComprFeatKey{
// 				FCompWithDependencies,
// 				FSBOMCompletenessDeclared,
// 				FPrimaryComponent,
// 				FCompWithSourceCode,
// 				FCompWithSupplier,
// 				FCompWithPurpose,
// 			},
// 		},

// 		// LicensingAndCompliance Category
// 		CatLicensingAndCompliance: {
// 			Key:    CatLicensingAndCompliance,
// 			Name:   "Licensing & Compliance",
// 			Weight: 15,
// 			Features: []ComprFeatKey{
// 				FCompWithLicenses,
// 				FCompWithValidLicenses,
// 				FCompWithDeclaredLicenses,
// 				FSBOMDataLicense,
// 				FCompNoDeprecatedLicenses,
// 				FCompNoRestrictiveLicenses,
// 			},
// 		},

// 		// Vulnerability Category
// 		CatVulnerabilityAndTrace: {
// 			Key:    CatVulnerabilityAndTrace,
// 			Name:   "Vulnerability & Traceability",
// 			Weight: 10,
// 			Features: []ComprFeatKey{
// 				FCompWithPURL,
// 				FCompWithCPE,
// 			},
// 		},

// 		// Structural Category
// 		CatStructural: {
// 			Key:    CatStructural,
// 			Name:   "Structural",
// 			Weight: 8,
// 			Features: []ComprFeatKey{
// 				FSBOMSpecDeclared,
// 				FSBOMSpecVersion,
// 				FSBOMFileFormat,
// 				FSBOMSchemaValid,
// 			},
// 		},

// 		// ComponentQualityInfo Category
// 		CatComponentQualityInfo: {
// 			Key:      CatComponentQualityInfo,
// 			Name:     "Component Quality (Info)",
// 			Weight:   0,
// 			Features: nil,
// 		},
// 	}

// 	// Default evaluation order
// 	order := []ComprCatKey{
// 		CatIdentification,
// 		CatProvenance,
// 		CatIntegrity,
// 		CatCompleteness,
// 		CatLicensingAndCompliance,
// 		CatVulnerabilityAndTrace,
// 		CatStructural,
// 		CatComponentQualityInfo,
// 	}

// 	return cats, order
// }

// func bindComprFeatures(doc sbom.Document) map[ComprFeatKey]ComprFeatSpec {
// 	return map[ComprFeatKey]ComprFeatSpec{
// 		// Identification
// 		FCompWithName:        {Key: FCompWithName, Weight: 0.40, Evaluate: extractors.CompWithName},
// 		FCompWithVersion:     {Key: FCompWithVersion, Weight: 0.35, Evaluate: extractors.CompWithVersion}, // FIXED: was mapped to completeness
// 		FCompWithIdentifiers: {Key: FCompWithIdentifiers, Weight: 0.25, Evaluate: extractors.CompWithUniqLocalIDs},

// 		// Provenance
// 		FSBOMCreationTimestamp: {Key: FSBOMCreationTimestamp, Weight: 0.20, Evaluate: extractors.SBOMCreationTimestamp},
// 		FSBOMAuthors:           {Key: FSBOMAuthors, Weight: 0.20, Evaluate: extractors.SBOMAuthors},
// 		FSBOMToolVersion:       {Key: FSBOMToolVersion, Weight: 0.20, Evaluate: extractors.SBOMCreationTool},
// 		FSBOMSupplier:          {Key: FSBOMSupplier, Weight: 0.15, Evaluate: extractors.SBOMSupplier},
// 		FSBOMNamespace:         {Key: FSBOMNamespace, Weight: 0.15, Evaluate: extractors.SBOMNamespace},
// 		FSBOMLifecycle:         {Key: FSBOMLifecycle, Weight: 0.10, Evaluate: extractors.SBOMLifeCycle},

// 		// Integrity
// 		FSBOMSignature:     {Key: FSBOMSignature, Weight: 0.10, Evaluate: extractors.SBOMSignature},
// 		FCompWithChecksums: {Key: FCompWithChecksums, Weight: 0.60, Evaluate: extractors.CompWithSHA1Plus},
// 		FCompWithSHA256:    {Key: FCompWithSHA256, Weight: 0.30, Evaluate: extractors.CompWithSHA256Plus},

// 		// Completeness
// 		FCompWithDependencies:     {Key: FCompWithDependencies, Weight: 0.25, Evaluate: extractors.CompWithDependencies},
// 		FSBOMCompletenessDeclared: {Key: FSBOMCompletenessDeclared, Weight: 0.15, Evaluate: extractors.CompWithCompleteness},
// 		FPrimaryComponent:         {Key: FPrimaryComponent, Weight: 0.20, Evaluate: extractors.SBOMWithPrimaryComponent},
// 		FCompWithSourceCode:       {Key: FCompWithSourceCode, Weight: 0.15, Evaluate: extractors.CompWithSourceCode},
// 		FCompWithSupplier:         {Key: FCompWithSupplier, Weight: 0.15, Evaluate: extractors.CompWithSupplier},
// 		FCompWithPurpose:          {Key: FCompWithPurpose, Weight: 0.10, Evaluate: extractors.CompWithPackagePurpose},

// 		// Licensing & Compliance
// 		FCompWithLicenses:          {Key: FCompWithLicenses, Weight: 0.20, Evaluate: extractors.CompWithLicenses},
// 		FCompWithValidLicenses:     {Key: FCompWithValidLicenses, Weight: 0.20, Evaluate: extractors.CompWithValidLicenses},
// 		FCompWithDeclaredLicenses:  {Key: FCompWithDeclaredLicenses, Weight: 0.15, Evaluate: extractors.CompWithDeclaredLicenses},
// 		FSBOMDataLicense:           {Key: FSBOMDataLicense, Weight: 0.10, Evaluate: extractors.SBOMDataLicense},
// 		FCompNoDeprecatedLicenses:  {Key: FCompNoDeprecatedLicenses, Weight: 0.15, Evaluate: extractors.CompWithDeprecatedLicenses},
// 		FCompNoRestrictiveLicenses: {Key: FCompNoRestrictiveLicenses, Weight: 0.20, Evaluate: extractors.CompWithRestrictiveLicenses},

// 		// Vulnerability & Traceability
// 		FCompWithPURL: {Key: FCompWithPURL, Weight: 0.50, Evaluate: extractors.CompWithPURL},
// 		FCompWithCPE:  {Key: FCompWithCPE, Weight: 0.50, Evaluate: extractors.CompWithCPE},

// 		// Structural
// 		FSBOMSpecDeclared: {Key: FSBOMSpecDeclared, Weight: 0.30, Evaluate: extractors.SBOMWithSpec},
// 		FSBOMSpecVersion:  {Key: FSBOMSpecVersion, Weight: 0.30, Evaluate: extractors.SBOMSpecVersion},
// 		FSBOMFileFormat:   {Key: FSBOMFileFormat, Weight: 0.20, Evaluate: extractors.SBOMFileFormat},
// 		FSBOMSchemaValid:  {Key: FSBOMSchemaValid, Weight: 0.20, Evaluate: extractors.SBOMSchemaValid},
// 	}
// }

// func bindProfFeatures() map[ProfFeatKey]ProfFeatSpec {
// 	return map[ProfFeatKey]ProfFeatSpec{
// 		PFSBOMSpec:                {Key: PFSBOMSpec, Required: true, Description: "Machine-readable SBOM (SPDX or CycloneDX declared)", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFSBOMSpecVersion:         {Key: PFSBOMSpec, Required: true, Description: "Supported spec version declared", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFSBOMSpecFileFormat:      {Key: PFSBOMSpec, Required: true, Description: "Supported file format", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompName:                {Key: PFSBOMSpec, Required: true, Description: "All components have names", Evaluate: profiles.CompWithNameCheck},
// 		PFCompVersion:             {Key: PFSBOMSpec, Required: true, Description: "Components have versions", Evaluate: profiles.CompWithVersionCheck},
// 		PFCompIdentifiers:         {Key: PFSBOMSpec, Required: true, Description: "Unique local identifiers PURL/CPE", Evaluate: profiles.CompWithUniqIDCheck},
// 		PFCompSupplier:            {Key: PFSBOMSpec, Required: true, Description: "Supplier/manufacturer info", Evaluate: profiles.CompWithSupplierCheck},
// 		PFCompDependencies:        {Key: PFSBOMSpec, Required: true, Description: "Dependency mapping present", Evaluate: profiles.CompWithDependencyCheck},
// 		PFSBOMCreationTimestamp:   {Key: PFSBOMSpec, Required: true, Description: "Creation timestamp (ISO-8601)", Evaluate: profiles.SbomWithTimeStampCheck},
// 		PFSBOMAuthors:             {Key: PFSBOMSpec, Required: true, Description: "Author/creator info", Evaluate: profiles.SbomWithAuthorsCheck},
// 		PFSBOMNamespace:           {Key: PFSBOMSpec, Required: true, Description: "Unique SBOM identifier", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompLicense:             {Key: PFSBOMSpec, Required: true, Description: "License info", Evaluate: profiles.CompWithLicensesCheck},
// 		PFCompChecksum:            {Key: PFSBOMSpec, Required: true, Description: "Checksums present", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompSourceCode:          {Key: PFSBOMSpec, Required: true, Description: "Source/VCS references", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFSBOMSchema:              {Key: PFSBOMSpec, Required: true, Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompChecksumSHA256:      {Key: PFSBOMSpec, Required: true, Description: "SHA-256 or stronger", Evaluate: profiles.CompWithSHA256ChecksumsCheck},
// 		PFSBOMSignature:           {Key: PFSBOMSpec, Required: true, Description: "Digital signature", Evaluate: profiles.SbomWithSignatureCheck},
// 		PFCompValidLicense:        {Key: PFSBOMSpec, Required: true, Description: "Valid SPDX license IDs", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFSBOMDataLicense:         {Key: PFSBOMSpec, Required: true, Description: "Data license (CC0-1.0 etc.)", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompPURLID:              {Key: PFSBOMSpec, Required: true, Description: "PURLs", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompCPEID:               {Key: PFSBOMSpec, Required: true, Description: "CPEs", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFSBOMCreationToolVersion: {Key: PFSBOMSpec, Required: true, Description: "Creator tool + version", Evaluate: profiles.SbomWithVersionCompliant},
// 		PFCompDeclaredLicense:     {Key: PFSBOMSpec, Required: true, Description: "Declared/original license", Evaluate: profiles.CompWithDeclaredLicensesCheck},
// 	}
// }

// func bindProfiles() map[ProfileKey]ProfSpec {
// 	return map[ProfileKey]ProfSpec{
// 		ProfileNTIA: {
// 			Key:  ProfileNTIA,
// 			Name: "NTIA Minimum Elements",
// 			Features: []ProfFeatKey{
// 				PFSBOMSpec,
// 				PFSBOMSpecVersion,
// 				PFSBOMSpecFileFormat,
// 				PFCompName,
// 				PFCompVersion,
// 				PFCompIdentifiers,
// 				PFCompSupplier,
// 				PFCompDependencies,
// 				PFSBOMCreationTimestamp,
// 				PFSBOMAuthors,
// 			},
// 		},

// 		ProfileBSI11: {
// 			Key:  ProfileBSI11,
// 			Name: "BSI TR-03183-2 v1.1",
// 			Features: []ProfFeatKey{
// 				PFSBOMSpec,
// 				PFSBOMSpecVersion,
// 				PFSBOMCreationTimestamp,
// 				PFSBOMAuthors,
// 				PFSBOMNamespace,
// 				PFCompName,
// 				PFCompVersion,
// 				PFCompLicense,
// 				PFCompChecksum,
// 				PFCompDependencies,
// 				PFCompSourceCode,
// 				PFCompSupplier,
// 			},
// 		},

// 		ProfileBSI20: {
// 			Key:  ProfileBSI20,
// 			Name: "BSI TR-03183-2 v2.0",
// 			Features: []ProfFeatKey{
// 				PFSBOMSpec,
// 				PFSBOMSpecVersion,
// 				PFSBOMCreationTimestamp,
// 				PFSBOMAuthors,
// 				PFSBOMSpecFileFormat,
// 				PFSBOMSchema,
// 				PFCompChecksum,
// 				PFCompChecksumSHA256,
// 				PFSBOMSignature,
// 				PFCompValidLicense,
// 				PFSBOMDataLicense,
// 				PFCompName,
// 				PFCompVersion,
// 				PFCompIdentifiers,
// 				PFCompPURLID,
// 				PFCompCPEID,
// 				PFCompDependencies,
// 			},
// 		},

//			ProfileOCT: {
//				Key:  ProfileOCT,
//				Name: "OpenChain Telco (OCT)",
//				Features: []ProfFeatKey{
//					PFSBOMSpec,
//					PFSBOMSpecVersion,
//					PFSBOMNamespace,
//					PFSBOMDataLicense,
//					PFSBOMCreationToolVersion,
//					PFCompName,
//					PFCompVersion,
//					PFCompIdentifiers,
//					PFCompLicense,
//					PFCompDeclaredLicense,
//					PFCompChecksum,
//					PFCompSourceCode,
//					PFCompSupplier,
//					PFCompDependencies,
//				},
//			},
//		}
//	}
package catalog
