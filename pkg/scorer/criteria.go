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

type criteria string

const (
	spec           criteria = "SBOM Specification"
	specVersion    criteria = "Spec Version"
	specFileFormat criteria = "Spec File Format"
	specIsParsable criteria = "Spec is parsable"

	compSupplierName criteria = "Components have supplier names"
	compWithNames    criteria = "Components have names"
	compWithVersion  criteria = "Components have versions"
	compWithUniqID   criteria = "Components have uniq ids"

	docWithRelations criteria = "Doc has relationships"
	docWithAuthors   criteria = "Doc has authors"
	docWithTimestamp criteria = "Doc has creation timestamp"

	docWithAllRequiredFields criteria = "Doc has all required fields"
	compWithLicenses         criteria = "Components have licenses"
	compWithChecksums        criteria = "Components have checksums"

	compWithValidLicenses      criteria = "Components have valid spdx licenses"
	compWithNoDepLicenses      criteria = "Components have no deprecated licenses"
	compWithMultipleLookupId   criteria = "Components have multiple vulnerability lookup ids"
	compWithAnyLookupId        criteria = "Components have any vulnerability lookup id"
	compWithPrimaryPackages    criteria = "Components have primary purpose defined"
	compWithRestrictedLicenses criteria = "Components have no restricted licenses"

	docShareLicense criteria = "Doc sharable license"
)

var criterias = map[criteria]func(d sbom.Document) score{}

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

func registerCriteria(name criteria, f func(sbom.Document) score) error {
	if _, ok := criterias[name]; ok {
		return fmt.Errorf("the criteria is being overwritten %s", name)
	}
	criterias[name] = f
	return nil
}
