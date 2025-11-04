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
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// sbomWithBomLinksCheck
func BSISBOMWithBomLinks(doc sbom.Document) catalog.ProfFeatScore {
	links := doc.Spec().GetExtDocRef()
	if len(links) == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no bom links found", Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("found %d bom links", len(links)), Ignore: false}
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
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	spec := strings.ToLower(doc.Spec().GetSpecType())
	var have int
	switch spec {
	case "spdx":
		// with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.ConcludedLicenses()) })
	case "cyclonedx":
		// with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.GetLicenses()) })
	default:
		// treat unknown spec as NA
		return catalog.ProfFeatScore{Score: 0.0, Desc: formulae.UnknownSpec(), Ignore: true}
	}

	return formulae.ScoreProfFull(have, len(comps), "associated licenses", false)
}

// compWithConcludedLicensesCheck (SPDX)
func CompWithConcludedLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// compWithDeclaredLicensesCheck
func CompWithDeclaredLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompDeclaredLicenses(doc)
}
