package scorer

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scvs"
)

const (
	green = "\033[32m"
	red   = "\033[31m"
	reset = "\033[0m"
	bold  = "\033[1m"
)

// Level: 123
func scvsSBOMMachineReadableCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMMachineReadable(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsSBOMAutomationCreationCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMCreationAutomated(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsSBOMUniqIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasUniqID(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsSBOMSigcheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasSignature(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsSBOMSigCorrectnessCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMSignatureCorrect(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsSBOMSigVerified(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMSignatureVerified(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsSBOMTimestampCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMTimestamped(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsSBOMRiskAnalysisCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMAnalyzedForRisk() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsSBOMInventoryListCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasInventoryOfDependencies() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsSBOMTestInventoryListCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMInventoryContainsTestComponents() {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsSBOMPrimaryCompCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsSBOMHasPrimaryComponents(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsCompHasIdentityIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasIdentityID(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHasOriginIDCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasOriginID(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsCompHasLicensesCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasLicenses(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
		s.setL1Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
		s.setL1Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 23
func scvsCompHasValidLicenseCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasVerifiedLicense(d) {
		s.setL3Score(green + bold + "✓" + reset)
		s.setL2Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
		s.setL2Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHasCopyright(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentHasCopyright(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHasModificationCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentContainsModificationChanges() {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHashCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if scvs.IsComponentContainsHash(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}
