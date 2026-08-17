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

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

// sbomWithRequiredFieldCheck scores the spec-mandated fields of the document
// header and of every package, blended into one value.
//
// The two halves are treated asymmetrically on purpose. Package completeness
// earns partial credit, but the document header is a gate: a document missing
// its own required fields is not spec-valid, so it scores zero however complete
// its packages are.
//
// Known wart, unchanged here: a document with zero components takes the partial
// path with a package score of 0 and lands on 5.0, where every sibling
// component check instead reports N/A and sets Ignore.
func sbomWithRequiredFieldCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())

	docOK := d.Spec().RequiredFields()
	noOfPkgs := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.RequiredFields()
	})
	pkgsOK := totalComponents > 0 && noOfPkgs == totalComponents

	switch {
	case !docOK:
		s.setScore(0.0)

	case pkgsOK:
		s.setScore(10.0)

	default:
		pkgScore := 0.0
		if totalComponents > 0 {
			pkgScore = (float64(noOfPkgs) / float64(totalComponents)) * 10.0
		}
		s.setScore((10.0 + pkgScore) / 2.0)
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
		return len(c.GetLicenses()) > 0
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
