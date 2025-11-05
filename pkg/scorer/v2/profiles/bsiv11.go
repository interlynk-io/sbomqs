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
	"github.com/samber/lo"
)

// BSISBOMSpec checks SBOM Formats
func BSISBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpec(doc)
}

// BSISBOMSpecVersion checks SBOM Spec Version
func BSISBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpecVersion(doc)
}

// BSISBOMBuildLifecycle checks Build Information
func BSISBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMLifeCycle(doc)
}

// BSISBOMWithDepedencies checks SBOM Depth
func BSISBOMWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

// BSISBOMWithAuthors checks SBOM Creator Info
func BSISBOMWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// BSISBOMWithTimeStamp checks Creation Time
func BSISBOMWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// BSISBOMNamespace checks URI/Namespace
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

// BSICompWithName checks Component Name
func BSICompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// BSICompWithVersion checks Component Version
func BSICompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// BSICompWithLicenses checks Component License
func BSICompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// BSICompWithHash checks Component Hash
func BSICompWithHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// BSICompWithSourceCodeURI checks Component Source URL
func BSICompWithSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeURL(doc)
}

// BSICompWithDownloadURI checks Component Download URL
func BSICompWithDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompDownloadCodeURL(doc)
}

// BSICompWithSourceCodeHash checks Component Source Hash
func BSICompWithSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeHash(doc)
}

// BSICompWithDependency checks Component Dependencies
func BSICompWithDependency(doc sbom.Document) catalog.ProfFeatScore {
	return CompDependencies(doc)
}

// ---------------------------------------------
// ---------------------------------------------

func BSICompWithExecutableURICheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(false)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetDownloadLocationURL() != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "executable url", false)
}

// TODO

// specWithVersionCompliant
// - 10 if spec+version in BSI-supported lists,
// - 5  if spec supported but version not in list,
// - 0  otherwise.
func BSISbomWithVersionCompliant(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		if lo.Contains(validBsiSpdxVersions, ver) {
			return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return catalog.ProfFeatScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}

	case string(sbom.SBOMSpecCDX):
		if lo.Contains(validBsiCdxVersions, ver) {
			return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return catalog.ProfFeatScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}

	default:
		return catalog.ProfFeatScore{Score: 0.0, Desc: fmt.Sprintf("unsupported spec: %s", spec)}
	}
}

// sbomWithURICheck
func BSISbomWithURICheck(doc sbom.Document) catalog.ProfFeatScore {
	if strings.TrimSpace(doc.Spec().GetURI()) == "" {
		return formulae.ScoreSBOMProfNA("no URI", false)
	}

	return formulae.ScoreSBOMProfFull("URI", false)
}

// TODO
func BSISBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	specToLower := strings.Trim(strings.ToLower(spec), " ")
	// version := doc.Spec().GetVersion()

	if specToLower == string(sbom.SBOMSpecSPDX) {
		return formulae.ScoreSBOMProfFull("spdx spec", false)
	} else if specToLower == string(sbom.SBOMSpecCDX) {
		return formulae.ScoreSBOMProfFull("cyclonedx spec", false)
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

func BSICompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(false)
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return formulae.ScoreProfFull(len(have), len(comps), "uniq IDs", false)
}
