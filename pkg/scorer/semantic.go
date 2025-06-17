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

package scorer

import (
	"fmt"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func sbomWithRequiredFieldCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())

	docOK := d.Spec().RequiredFields()
	noOfPkgs := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.RequiredFields()
	})
	pkgsOK := false
	if totalComponents > 0 && noOfPkgs == totalComponents {
		pkgsOK = true
	}

	var docScore, pkgScore float64

	if !docOK && pkgsOK {
		docScore = 0
		pkgScore = 10.0
		s.setScore((docScore + pkgScore) / 2.0)
		s.setScore(0.0)
	}

	if docOK && !pkgsOK {
		docScore = 10.0
		if totalComponents > 0 {
			pkgScore = (float64(noOfPkgs) / float64(totalComponents)) * 10.0
		}
		s.setScore((docScore + pkgScore) / 2.0)
	}

	if docOK && pkgsOK {
		s.setScore(10.0)
	}

	s.setDesc(fmt.Sprintf("Doc Fields:%t Pkg Fields:%t", docOK, pkgsOK))

	return *s
}

func compWithLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Licenses()) > 0
	})

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have licenses", withLicenses, totalComponents))

	return *s
}

func compWithChecksumsCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withChecksums := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetChecksums()) > 0
	})

	if totalComponents > 0 {
		s.setScore((float64(withChecksums) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}
