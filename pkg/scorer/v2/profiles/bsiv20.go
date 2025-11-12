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

package profiles

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// sbomWithBomLinksCheck
func BSISBOMWithBomLinks(doc sbom.Document) catalog.ProfFeatScore {
	links := doc.Spec().GetExtDocRef()
	if len(links) == 0 {
		formulae.ScoreSBOMProfNA("no bom links found", true)
	}
	return formulae.ScoreSBOMProfFull("bom links", true)
}

// BSISBOMWithVulnerabilities (BSI v2.1 note in your comments)
func BSISBOMWithVulnerabilities(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMVulnerabilities(doc)
}

// BSISBOMWithSignature
func BSISBOMWithSignature(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSignature(doc)
}

// compWithAssociatedLicensesCheck: concluded for SPDX, effective for CDX components
func BSICompWithAssociatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// compWithConcludedLicensesCheck (SPDX)
func CompWithConcludedLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompConcludedLicenses(doc)
}

// compWithDeclaredLicensesCheck
func CompWithDeclaredLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompDeclaredLicenses(doc)
}
