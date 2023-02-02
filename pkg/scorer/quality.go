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

func compWithAllIdScore(d sbom.Document) score {
	s := newScore(CategoryQuality, string(compWithAllId))

	totalComponents := len(d.Components())

	withCpe := lo.FilterMap(d.Components(), func(c sbom.Component, _ int) (string, bool) {
		if len(c.Cpes()) > 0 {
			return c.ID(), true
		}
		return c.ID(), false
	})
	withPurl := lo.FilterMap(d.Components(), func(c sbom.Component, _ int) (string, bool) {
		if len(c.Purls()) > 0 {
			return c.ID(), true
		}
		return c.ID(), false
	})

	compsWithCPE := len(withCpe)
	compsWithPURL := len(withPurl)

	cpeScore := (float64(compsWithCPE) / float64(totalComponents)) * 10.0
	purlScore := (float64(compsWithPURL) / float64(totalComponents)) * 10.0

	avg_score := ((float64(cpeScore) + float64(purlScore)) / 2.0)

	s.setScore(avg_score)

	s.setDesc(fmt.Sprintf("comp with uniq ids: cpe:%d, purl:%d, total:%d", compsWithCPE, compsWithPURL, totalComponents))

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
	withDepLicense := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		deps := lo.CountBy(c.Licenses(), func(l sbom.License) bool {
			return l.Deprecated()
		})
		return deps > 0
	})

	finalScore := (float64(totalComponents-withDepLicense) / float64(totalComponents)) * 10.0
	s.setScore(finalScore)
	s.setDesc(fmt.Sprintf("%d/%d components have deprecated licenses", withDepLicense, totalComponents))
	return *s
}
