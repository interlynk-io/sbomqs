package scorer

import (
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scvs"
	"github.com/samber/lo"
)

const (
	green = "\033[32m"
	red   = "\033[31m"
	reset = "\033[0m"
	bold  = "\033[1m"
)

func scvsSBOMMachineReadableCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMMachineReadable(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMAutomationCreationCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMCreationAutomated(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMUniqIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasUniqID(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMSigcheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasSignature(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMSigCorrectnessCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMSignatureCorrect(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMSigVerified(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMSignatureVerified(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMTimestampCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMTimestamped(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMRiskAnalysisCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMAnalyzedForRisk() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMInventoryListCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasInventoryOfDependencies() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMTestInventoryListCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMInventoryContainsTestComponents() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsSBOMPrimaryCompCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasPrimaryComponents(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasIdentityIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasIdentityID(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasOriginIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasOriginID(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasLicensesCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasLicenses(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasValidLicenseCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasVerifiedLicense() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasCopyright(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasCopyright(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHasModificationCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentContainsModificationChanges() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func scvsCompHashCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentContainsHash() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func docWithTimeStampScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMTimestamped(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}

	return *s
}

func docWithNamespaceScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if d.Spec().GetNamespace() != "" {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}

	return *s
}

func sbomMachineReadable() {
	// sbomFormat and sbomFileFormat
}

func sbomFormat(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	specs := sbom.SupportedSBOMSpecs()
	// s.setDesc(fmt.Sprintf("provided sbom is in a supported sbom format of %s", strings.Join(specs, ",")))

	for _, spec := range specs {
		if d.Spec().GetSpecType() == spec {
			s.setL3Score(green + bold + "✓" + reset)
			s.setL2Score(green + bold + "✓" + reset)
			s.setL1Score(green + bold + "✓" + reset)
		}
	}
	return *s
}

func sbomFileFormat(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if fileFormat := d.Spec().FileFormat(); fileFormat == "json" || fileFormat == "tag-value" {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func sbomCreatorToolWithVersion(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if tools := d.Tools(); tools != nil {
		for _, tool := range tools {
			name := tool.GetName()
			version := tool.GetVersion()
			if name != "" && version != "" {
				s.setL3Score(green + bold + "✓" + reset)
				s.setL2Score(green + bold + "✓" + reset)
				s.setL1Score(green + bold + "✓" + reset)
			}
		}
	}
	return *s
}

func sbomUniqID(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if ns := d.Spec().GetNamespace(); ns != "" {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	}
	return *s
}

func compWithUniqIDScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setL3Score(red + bold + "✗" + reset)
		// s.setIgnore(true)
		return *s
	}

	compIDs := lo.FilterMap(d.Components(), func(c sbom.GetComponent, i int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{d.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	// uniqComps := lo.Uniq(compIDs)

	if totalComponents > 0 {
		if len(compIDs) == totalComponents {
			s.setL3Score(green + bold + "✓" + reset)
		} else {
			s.setL3Score(red + bold + "✗" + reset)
		}
	}
	// s.setDesc(fmt.Sprintf("%d/%d have unique ID's", len(compIDs), totalComponents))
	return *s
}

func compWithLicensesScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(green + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}
	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Licenses()) > 0
	})

	if totalComponents > 0 {
		if withLicenses == totalComponents {
			s.setL3Score(green + bold + "✓" + reset)
			s.setL2Score(green + bold + "✓" + reset)
			s.setL1Score(green + bold + "✓" + reset)
		} else {
			s.setL3Score(red + bold + "✗" + reset)
			s.setL2Score(red + bold + "✗" + reset)
			s.setL1Score(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have licenses", withLicenses, totalComponents))

	return *s
}

func compWithChecksumsScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setL3Score(red + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}

	withChecksums := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetChecksums()) > 0
	})

	if totalComponents > 0 {
		if withChecksums == totalComponents {
			s.setL3Score(green + bold + "✓" + reset)
		} else {
			s.setL3Score(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}

func compWithCopyrightScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setL3Score(red + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}

	withCopyrights := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetCopyRight()) > 0
	})

	if totalComponents > 0 {
		if withCopyrights == totalComponents {
			s.setL3Score(green + bold + "✓" + reset)
		} else {
			s.setL3Score(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}
