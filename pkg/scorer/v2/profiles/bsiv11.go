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
	"time"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

func BSISBOMWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Authors())

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "0 authors",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("%d authors", total),
		Ignore: false,
	}
}

// TODO
func BSICompWithHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.GetLicenses())
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

// // TODO
// func BSICompWithSourceCode(doc sbom.Document) catalog.ProfFeatScore {
// 	comps := doc.Components()
// 	if len(comps) == 0 {
// 		formulae.SetNA()
// 	}

// 	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
// 		return common.AreLicensesValid(c.GetLicenses())
// 	})

// 	return catalog.ProfFeatScore{
// 		Score:  formulae.PerComponentScore(have, len(comps)),
// 		Desc:   formulae.CompDescription(have, len(comps), "names"),
// 		Ignore: false,
// 	}
// }

func BSICompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.GetLicenses())
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSISBOMWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("timestamp"),
			Ignore: false,
		}
	}

	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return catalog.ProfFeatScore{
				Score:  formulae.BooleanScore(false),
				Desc:   fmt.Sprintf("invalid timestamp: %s", ts),
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   ts,
		Ignore: false,
	}
}

func BSICompWithSHA256Checksums(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return lo.ContainsBy(c.GetChecksums(), func(checksum sbom.GetChecksum) bool {
			return lo.Contains(algos, checksum.GetAlgo())
		})
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSISBOMWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	var have int
	if doc.PrimaryComp() != nil {
		have = doc.PrimaryComp().GetTotalNoOfDependencies()
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("primary comp has %d dependencies", have),
		Ignore: false,
	}
}

func BSICompWithSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetSourceCodeURL() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSICompWithSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.SourceCodeHash() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSICompWithExecutableURICheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetDownloadLocationURL() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

// TODO
func BSICompWithDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetDownloadLocationURL() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSICompWithDependency(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.HasRelationShips()
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

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
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no URI",
			Ignore: false,
		}
	}
	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

// sbomWithURICheck
func BSISBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	specToLower := strings.Trim(strings.ToLower(spec), " ")

	if specToLower == string(sbom.SBOMSpecSPDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has spdx spec",
			Ignore: false,
		}
	} else if specToLower == string(sbom.SBOMSpecCDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has cyclonedx spec",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

// TODO
func BSISBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	specToLower := strings.Trim(strings.ToLower(spec), " ")
	// version := doc.Spec().GetVersion()

	if specToLower == string(sbom.SBOMSpecSPDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has spdx spec",
			Ignore: false,
		}
	} else if specToLower == string(sbom.SBOMSpecCDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has cyclonedx spec",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

// TODO
func BSISBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	specToLower := strings.Trim(strings.ToLower(spec), " ")
	// version := doc.Spec().GetVersion()

	if specToLower == string(sbom.SBOMSpecSPDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has spdx spec",
			Ignore: false,
		}
	} else if specToLower == string(sbom.SBOMSpecCDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has cyclonedx spec",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

// TODO
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	specToLower := strings.Trim(strings.ToLower(spec), " ")
	// version := doc.Spec().GetVersion()

	if specToLower == string(sbom.SBOMSpecSPDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has spdx spec",
			Ignore: false,
		}
	} else if specToLower == string(sbom.SBOMSpecCDX) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "has cyclonedx spec",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "has URI",
		Ignore: false,
	}
}

func BSICompWithName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetName() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSICompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetVersion() != ""
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func BSICompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.SetNA()
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(len(have), len(comps)),
		Desc:   formulae.CompDescription(len(have), len(comps), "names"),
		Ignore: false,
	}
}

// TODO
