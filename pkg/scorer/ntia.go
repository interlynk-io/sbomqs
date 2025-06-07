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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func compSupplierCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withNames := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.Suppliers().IsPresent()
	})

	if totalComponents > 0 {
		s.setScore((float64(withNames) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have supplier names", withNames, totalComponents))

	return *s
}

func compWithNameCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withNames := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.GetName() != ""
	})
	if totalComponents > 0 {
		s.setScore((float64(withNames) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have names", withNames, totalComponents))

	return *s
}

func compWithVersionCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withVersions := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.GetVersion() != ""
	})
	if totalComponents > 0 {
		s.setScore((float64(withVersions) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have versions", withVersions, totalComponents))

	return *s
}

func compWithUniqIDCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	compIDs := lo.FilterMap(d.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{d.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	// uniqComps := lo.Uniq(compIDs)

	if totalComponents > 0 {
		s.setScore((float64(len(compIDs)) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have unique ID's", len(compIDs), totalComponents))
	return *s
}

func docWithDepedenciesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	var totalDependencies int
	if d.PrimaryComp() != nil {
		totalDependencies = d.PrimaryComp().GetTotalNoOfDependencies()
	}
	if totalDependencies > 0 {
		s.setScore(10.0)
	}
	s.setDesc(fmt.Sprintf("doc has %d dependencies ", totalDependencies))
	return *s
}

func docWithAuthorsCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	noOfAuthors := len(d.Authors())
	noOfTools := len(d.Tools())

	totalAuthors := noOfAuthors + noOfTools

	if totalAuthors > 0 {
		s.setScore(10.0)
	}
	s.setDesc(fmt.Sprintf("doc has %d authors", totalAuthors))

	return *s
}

func docWithTimeStampCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if d.Spec().GetCreationTimestamp() != "" {
		s.setScore(10.0)
	}

	s.setDesc(fmt.Sprintf("doc has creation timestamp %s", d.Spec().GetCreationTimestamp()))
	return *s
}
