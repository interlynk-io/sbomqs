package scorer

import (
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

const (
	green = "\033[32m"
	red   = "\033[31m"
	reset = "\033[0m"
	bold  = "\033[1m"
)

func docWithTimeStampScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if d.Spec().GetCreationTimestamp() != "" {
		s.setScore(green + bold + "✓" + reset)
	}

	return *s
}

func docWithNamespaceScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	if d.Spec().GetNamespace() != "" {
		s.setScore(green + bold + "✓" + reset)
	}

	return *s
}

func specScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	specs := sbom.SupportedSBOMSpecs()
	// s.setDesc(fmt.Sprintf("provided sbom is in a supported sbom format of %s", strings.Join(specs, ",")))

	for _, spec := range specs {
		if d.Spec().GetSpecType() == spec {
			s.setScore(green + bold + "✓" + reset)
		}
	}
	return *s
}

func compWithUniqIDScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(red + bold + "✗" + reset)
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
			s.setScore(green + bold + "✓" + reset)
		} else {
			s.setScore(red + bold + "✗" + reset)
		}
	}
	// s.setDesc(fmt.Sprintf("%d/%d have unique ID's", len(compIDs), totalComponents))
	return *s
}

func compWithLicensesScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(red + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}
	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Licenses()) > 0
	})

	if totalComponents > 0 {
		if withLicenses == totalComponents {
			s.setScore(green + bold + "✓" + reset)
		} else {
			s.setScore(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have licenses", withLicenses, totalComponents))

	return *s
}

func compWithChecksumsScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(red + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}

	withChecksums := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetChecksums()) > 0
	})

	if totalComponents > 0 {
		if withChecksums == totalComponents {
			s.setScore(green + bold + "✓" + reset)
		} else {
			s.setScore(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}

func compWithCopyrightScvsCheck(d sbom.Document, c *scvsCheck) scvsScore {
	s := newScoreFromScvsCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(red + bold + "✗" + reset)
		// s.setDesc("N/A (no components)")
		// s.setIgnore(true)
		return *s
	}

	withCopyrights := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetCopyRight()) > 0
	})

	if totalComponents > 0 {
		if withCopyrights == totalComponents {
			s.setScore(green + bold + "✓" + reset)
		} else {
			s.setScore(red + bold + "✗" + reset)
		}
	}

	// s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}
