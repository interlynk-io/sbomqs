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

	docShareLicense criterion = "Doc sharable license"
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
