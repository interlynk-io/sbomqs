// Copyright 2023 Interlynk.io
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

package scorer

import (
	"fmt"
	"math"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func compWithValidLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	compScores := lo.Map(d.Components(), func(c sbom.GetComponent, _ int) float64 {
		tl := len(c.Licenses())

		validLic := lo.CountBy(c.Licenses(), func(l licenses.License) bool {
			return l.Deprecated() || l.Source() == "custom"
		})

		return (float64(validLic) / float64(tl)) * 10.0
	})

	totalCompScore := lo.Reduce(compScores, func(agg float64, a float64, _ int) float64 {
		if !math.IsNaN(a) {
			return agg + a
		}
		return agg
	}, 0.0)

	finalScore := (totalCompScore / float64(totalComponents))
	compsWithValidScores := lo.CountBy(compScores, func(score float64) bool {
		return score > 0.0
	})

	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components with valid license ", compsWithValidScores, totalComponents))

	return *s
}

func compWithPrimaryPackageCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withPurpose := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.PrimaryPurpose() != "" && lo.Contains(sbom.SupportedPrimaryPurpose(d.Spec().GetSpecType()), strings.ToLower(c.PrimaryPurpose()))
	})

	finalScore := (float64(withPurpose) / float64(totalComponents)) * 10.0
	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have primary purpose specified", withPurpose, totalComponents))
	return *s
}

func compWithNoDepLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	totalLicenses := lo.Reduce(d.Components(), func(agg int, c sbom.GetComponent, _ int) int {
		return agg + len(c.Licenses())
	}, 0)

	withDepLicense := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		deps := lo.CountBy(c.Licenses(), func(l licenses.License) bool {
			return l.Deprecated()
		})
		return deps > 0
	})

	if totalLicenses == 0 {
		s.setScore(0.0)
		s.setDesc("no licenses found")
	} else {
		finalScore := (float64(totalComponents-withDepLicense) / float64(totalComponents)) * 10.0
		s.setScore(finalScore)
		s.setDesc(fmt.Sprintf("%d/%d components have deprecated licenses", withDepLicense, totalComponents))
	}
	return *s
}

func compWithRestrictedLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	totalLicenses := lo.Reduce(d.Components(), func(agg int, c sbom.GetComponent, _ int) int {
		return agg + len(c.Licenses())
	}, 0)

	withRestrictLicense := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		rest := lo.CountBy(c.Licenses(), func(l licenses.License) bool {
			return l.Restrictive()
		})
		return rest > 0
	})

	if totalLicenses == 0 {
		s.setScore(0.0)
		s.setDesc("no licenses found")
	} else {
		finalScore := (float64(totalComponents-withRestrictLicense) / float64(totalComponents)) * 10.0
		s.setScore(finalScore)
		s.setDesc(fmt.Sprintf("%d/%d components have restricted licenses", withRestrictLicense, totalComponents))
	}
	return *s
}

func compWithAnyLookupIDCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withAnyLookupID := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		if len(c.Cpes()) > 0 || len(c.Purls()) > 0 {
			return true
		}
		return false
	})

	finalScore := (float64(withAnyLookupID) / float64(totalComponents)) * 10.0

	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have any lookup id", withAnyLookupID, totalComponents))

	return *s
}

func compWithMultipleIDCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withMultipleID := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		if len(c.Cpes()) > 0 && len(c.Purls()) > 0 {
			return true
		}
		return false
	})

	finalScore := (float64(withMultipleID) / float64(totalComponents)) * 10.0

	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have multiple lookup id", withMultipleID, totalComponents))

	return *s
}

func docWithCreatorCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalTools := len(d.Tools())

	withCreatorAndVersion := lo.CountBy(d.Tools(), func(t sbom.GetTool) bool {
		return t.GetName() != "" && t.GetVersion() != ""
	})

	finalScore := (float64(withCreatorAndVersion) / float64(totalTools)) * 10.0

	s.setScore(finalScore)
	s.setDesc(fmt.Sprintf("%d/%d tools have creator and version", withCreatorAndVersion, totalTools))
	return *s
}

func docWithPrimaryComponentCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if d.PrimaryComponent() {
		s.setScore(10.0)
		s.setDesc("primary component found")
		return *s
	}
	s.setScore(0.0)
	s.setDesc("no primary component found")
	return *s
}
