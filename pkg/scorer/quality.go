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

func compWithValidLicensesScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithValidLicenses))

	totalComponents := len(d.Components())

	compScores := lo.Map(d.Components(), func(c sbom.Component, _ int) float64 {
		tl := len(c.Licenses())

		validLic := lo.CountBy(c.Licenses(), func(l sbom.License) bool {
			return l.ValidSpdxLicense()
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

func compWithPrimaryPackageScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithPrimaryPackages))

	totalComponents := len(d.Components())

	withPurpose := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		return c.PrimaryPurpose() != "" && lo.Contains(sbom.SupportedPrimaryPurpose(d.Spec().Name()), strings.ToLower(c.PrimaryPurpose()))
	})

	finalScore := (float64(withPurpose) / float64(totalComponents)) * 10.0
	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have primary purpose specified", withPurpose, totalComponents))
	return *s
}

func compWithNoDepLicensesScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithNoDepLicenses))
	totalComponents := len(d.Components())

	totalLicenses := lo.Reduce(d.Components(), func(agg int, c sbom.Component, _ int) int {
		return agg + len(c.Licenses())
	}, 0)

	withDepLicense := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		deps := lo.CountBy(c.Licenses(), func(l sbom.License) bool {
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

func compWithRestrictedLicensesScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithRestrictedLicenses))
	totalComponents := len(d.Components())

	totalLicenses := lo.Reduce(d.Components(), func(agg int, c sbom.Component, _ int) int {
		return agg + len(c.Licenses())
	}, 0)

	withRestrictLicense := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		rest := lo.CountBy(c.Licenses(), func(l sbom.License) bool {
			return licenses.RestrictedLicense(l.Name())
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

func compWithAnyLookupIdScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithAnyLookupId))

	totalComponents := len(d.Components())

	withAnyLookupId := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		if len(c.Cpes()) > 0 || len(c.Purls()) > 0 {
			return true
		}
		return false
	})

	finalScore := (float64(withAnyLookupId) / float64(totalComponents)) * 10.0

	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have any lookup id", withAnyLookupId, totalComponents))

	return *s
}

func compWithMultipleIdScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithMultipleLookupId))

	totalComponents := len(d.Components())

	withMultipleId := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		if len(c.Cpes()) > 0 && len(c.Purls()) > 0 {
			return true
		}
		return false
	})

	finalScore := (float64(withMultipleId) / float64(totalComponents)) * 10.0

	s.setScore(finalScore)

	s.setDesc(fmt.Sprintf("%d/%d components have multiple lookup id", withMultipleId, totalComponents))

	return *s
}

func docWithCreatorScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(docWithCreator))

	totalTools := len(d.Tools())

	withCreatorAndVersion := lo.CountBy(d.Tools(), func(t sbom.Tool) bool {
		return t.Name() != "" && t.Version() != ""
	})

	finalScore := (float64(withCreatorAndVersion) / float64(totalTools)) * 10.0

	s.setScore(finalScore)
	s.setDesc(fmt.Sprintf("%d/%d tools have creator and version", withCreatorAndVersion, totalTools))
	return *s
}
