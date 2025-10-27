package profiles

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

func CompWithLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
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

func CompWithSHA256ChecksumsCheck(doc sbom.Document) catalog.ProfFeatScore {
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

func CompWithSourceCodeURICheck(doc sbom.Document) catalog.ProfFeatScore {
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

func CompWithSourceCodeHashCheck(doc sbom.Document) catalog.ProfFeatScore {
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

func CompWithExecutableURICheck(doc sbom.Document) catalog.ProfFeatScore {
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

func CompWithDependencyCheck(doc sbom.Document) catalog.ProfFeatScore {
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
func SbomWithVersionCompliant(doc sbom.Document) catalog.ProfFeatScore {
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
func SbomWithURICheck(doc sbom.Document) catalog.ProfFeatScore {
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
