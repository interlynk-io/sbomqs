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
	"github.com/samber/lo"
)

func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAutomationSpec(doc)
}

func CompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.Suppliers().IsPresent()
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func CompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

func CompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

func CompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	return CompWithUniqID(doc)
}

func SbomWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

func SbomWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

func SbomWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}
