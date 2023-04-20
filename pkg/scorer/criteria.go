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
	"fmt"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

type category string

const (
	CategoryStrucutral         category = "Structural"
	CategoryNTIAMiniumElements category = "NTIA-minimum-elements"
	CategorySemantic           category = "Semantic"
	CategoryQuality            category = "Quality"
	CategorySharing            category = "Sharing"
)

var Categories = []string{string(CategoryNTIAMiniumElements), string(CategoryQuality), string(CategorySemantic), string(CategorySharing), string(CategoryStrucutral)}

func CategorieMapWithCriteria(categorie string) []string {
	switch categorie {
	case string(CategoryNTIAMiniumElements):
		return []string{
			string(compSupplierName),
			string(compWithNames),
			string(compWithVersion),
			string(compWithUniqID),
			string(docWithRelations),
			string(docWithAuthors),
			string(docWithTimestamp)}
	case string(CategoryQuality):
		return []string{
			string(compWithValidLicenses),
			string(compWithPrimaryPackages),
			string(compWithNoDepLicenses),
			string(compWithRestrictedLicenses),
			string(compWithMultipleLookupId),
			string(compWithAnyLookupId),
			string(docWithCreator)}
	case string(CategorySemantic):
		return []string{
			string(docWithAllRequiredFields),
			string(compWithLicenses),
			string(compWithChecksums)}
	case string(CategorySharing):
		return []string{
			string(docShareLicense)}
	case string(CategoryStrucutral):
		return []string{
			string(spec),
			string(specVersion),
			string(specFileFormat),
			string(specIsParsable)}
	default:
		return []string{}

	}
}

type criterion string

const (
	spec           criterion = "SBOM Specification"
	specVersion    criterion = "Spec Version"
	specFileFormat criterion = "Spec File Format"
	specIsParsable criterion = "Spec is parsable"

	compSupplierName criterion = "Components have supplier names"
	compWithNames    criterion = "Components have names"
	compWithVersion  criterion = "Components have versions"
	compWithUniqID   criterion = "Components have uniq ids"

	docWithRelations criterion = "Doc has relationships"
	docWithAuthors   criterion = "Doc has authors"
	docWithTimestamp criterion = "Doc has creation timestamp"

	docWithAllRequiredFields criterion = "Doc has all required fields"
	compWithLicenses         criterion = "Components have licenses"
	compWithChecksums        criterion = "Components have checksums"

	compWithValidLicenses      criterion = "Components have valid spdx licenses"
	compWithNoDepLicenses      criterion = "Components have no deprecated licenses"
	compWithMultipleLookupId   criterion = "Components have multiple vulnerability lookup ids"
	compWithAnyLookupId        criterion = "Components have any vulnerability lookup id"
	compWithPrimaryPackages    criterion = "Components have primary purpose defined"
	compWithRestrictedLicenses criterion = "Components have no restricted licenses"
	docWithCreator             criterion = "Doc has creator tool and version"

	docShareLicense criterion = "Doc shareable license"
)

var criteria = map[criterion]func(d sbom.Document) score{}

func init() {
	//structural
	_ = registerCriteria(spec, specScore)
	_ = registerCriteria(specVersion, specVersionScore)
	_ = registerCriteria(specFileFormat, specFileFormatScore)
	_ = registerCriteria(specIsParsable, specParsableScore)

	//ntia minimum
	_ = registerCriteria(compSupplierName, compSupplierScore)
	_ = registerCriteria(compWithNames, compWithNameScore)
	_ = registerCriteria(compWithVersion, compWithVersionScore)
	_ = registerCriteria(compWithUniqID, compWithUniqIDScore)

	_ = registerCriteria(docWithRelations, docWithDepedenciesScore)
	_ = registerCriteria(docWithAuthors, docWithAuthorsScore)
	_ = registerCriteria(docWithTimestamp, docWithTimeStampScore)

	//semantic
	_ = registerCriteria(docWithAllRequiredFields, docWithRequiredFieldScore)
	_ = registerCriteria(compWithLicenses, compWithLicenseScore)
	_ = registerCriteria(compWithChecksums, compWithChecksumsScore)

	//quality
	_ = registerCriteria(compWithValidLicenses, compWithValidLicensesScore)
	_ = registerCriteria(compWithNoDepLicenses, compWithNoDepLicensesScore)
	_ = registerCriteria(compWithPrimaryPackages, compWithPrimaryPackageScore)
	_ = registerCriteria(compWithRestrictedLicenses, compWithRestrictedLicensesScore)
	_ = registerCriteria(compWithAnyLookupId, compWithAnyLookupIdScore)
	_ = registerCriteria(compWithMultipleLookupId, compWithMultipleIdScore)
	_ = registerCriteria(docWithCreator, docWithCreatorScore)

	//sharing
	_ = registerCriteria(docShareLicense, sharableLicenseScore)

}

func registerCriteria(name criterion, f func(sbom.Document) score) error {
	if _, ok := criteria[name]; ok {
		return fmt.Errorf("the criteria is being overwritten %s", name)
	}
	criteria[name] = f
	return nil
}

type CriteriaArg string

const (
	DOCLICENCE               CriteriaArg = "doc-license"
	COMPNORESTRICLICENCE     CriteriaArg = "comp-no-restric-licence"
	COMPPRIMARYPURPOSE       CriteriaArg = "comp-primary-purpose"
	COMPNODEPRECATLICENCE    CriteriaArg = "comp-no-deprecat-licence"
	COMPVALIDLICENCE         CriteriaArg = "comp-valid-licence"
	COMPCHECKSUMS            CriteriaArg = "comp-checksums"
	COMPLICENCE              CriteriaArg = "comp-licence"
	DOCALLREQFILEDS          CriteriaArg = "doc-all-req-fileds"
	DOCTIMESTAMP             CriteriaArg = "doc-timestamp"
	DOCAUTHOR                CriteriaArg = "doc-author"
	DOCRELATIONSHIP          CriteriaArg = "doc-relationship"
	COMPUNIQIDS              CriteriaArg = "comp-uniq-ids"
	COMPVERSION              CriteriaArg = "comp-version"
	COMPNAME                 CriteriaArg = "comp-name"
	COMPSUPPLIERNAME         CriteriaArg = "comp-supplier-name"
	SPECPARSABLE             CriteriaArg = "spec-parsable"
	SPECFILEFORMAT           CriteriaArg = "spec-file-format"
	SPECVERSION              CriteriaArg = "spec-version"
	SBOMSPEC                 CriteriaArg = "sbom-spec"
	COMPANYVULNERABILITYID   CriteriaArg = "comp-any-vulnerability-id"
	COMPMULTIVULNERABILITYID CriteriaArg = "comp-multi-vulnerability-id"
	DOCCREATORTOOL           CriteriaArg = "doc-creator-tool"
)

var CriteriaArgs = []string{
	string(DOCLICENCE),
	string(COMPNORESTRICLICENCE),
	string(COMPPRIMARYPURPOSE),
	string(COMPNODEPRECATLICENCE),
	string(COMPVALIDLICENCE),
	string(COMPCHECKSUMS),
	string(COMPLICENCE),
	string(DOCALLREQFILEDS),
	string(DOCTIMESTAMP),
	string(DOCAUTHOR),
	string(DOCRELATIONSHIP),
	string(COMPUNIQIDS),
	string(COMPVERSION),
	string(COMPNAME),
	string(COMPSUPPLIERNAME),
	string(SPECPARSABLE),
	string(SPECFILEFORMAT),
	string(SPECVERSION),
	string(SBOMSPEC),
	string(COMPANYVULNERABILITYID),
	string(COMPMULTIVULNERABILITYID),
	string(DOCCREATORTOOL),
}

var CriteriaArgMap = map[CriteriaArg]string{
	DOCLICENCE:               string(docShareLicense),
	COMPNORESTRICLICENCE:     string(compWithRestrictedLicenses),
	COMPPRIMARYPURPOSE:       string(compWithPrimaryPackages),
	COMPNODEPRECATLICENCE:    string(compWithNoDepLicenses),
	COMPVALIDLICENCE:         string(compWithValidLicenses),
	COMPCHECKSUMS:            string(compWithChecksums),
	COMPLICENCE:              string(compWithLicenses),
	DOCALLREQFILEDS:          string(docWithAllRequiredFields),
	DOCTIMESTAMP:             string(docWithTimestamp),
	DOCAUTHOR:                string(docWithAuthors),
	DOCRELATIONSHIP:          string(docWithRelations),
	COMPUNIQIDS:              string(compWithUniqID),
	COMPVERSION:              string(compWithVersion),
	COMPNAME:                 string(compWithNames),
	COMPSUPPLIERNAME:         string(compSupplierName),
	SPECPARSABLE:             string(specIsParsable),
	SPECFILEFORMAT:           string(specFileFormat),
	SPECVERSION:              string(specVersion),
	SBOMSPEC:                 string(spec),
	COMPANYVULNERABILITYID:   string(compWithAnyLookupId),
	COMPMULTIVULNERABILITYID: string(compWithMultipleLookupId),
	DOCCREATORTOOL:           string(docWithCreator),
}
