package scvs

import (
	"github.com/interlynk-io/sbomqs/pkg/sbom"
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

	if IsSBOMMachineReadable(d, s) {
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

	if IsSBOMCreationAutomated(d) {
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

	if IsSBOMHasUniqID(d) {
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

	if IsSBOMHasSignature(d) {
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

	if IsSBOMSignatureCorrect(d) {
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

	if IsSBOMSignatureVerified(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsSBOMTimestampCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if IsSBOMTimestamped(d) {
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

	if IsSBOMAnalyzedForRisk() {
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

	if IsSBOMHasInventoryOfDependencies() {
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

	if IsSBOMInventoryContainsTestComponents() {
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

	if IsSBOMHasPrimaryComponents(d) {
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

	if IsComponentHasIdentityID(d) {
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

	if IsComponentHasOriginID(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 123
func scvsCompHasLicensesCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if IsComponentHasLicenses(d) {
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

	if IsComponentHasVerifiedLicense(d) {
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

	if IsComponentHasCopyright(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHasModificationCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if IsComponentContainsModificationChanges() {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}

// Level: 3
func scvsCompHashCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if IsComponentContainsHash(d) {
		s.setL3Score(green + bold + "✓" + reset)
	} else {
		s.setL3Score(red + bold + "✗" + reset)
	}
	return *s
}
