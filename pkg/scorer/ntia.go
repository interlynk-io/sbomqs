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

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

func compWithSupplierCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withNames := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.Suppliers().GetName()) != ""
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

// compWithUniqIDCheck implements the NTIA minimum element "Other Unique
// Identifiers": "At least one additional identifier if available (e.g., CPE,
// PURL, SWID)."
//
// Mappings:
//   - SPDX: PackageExternalRefs (PURL), PackageCPEs
//   - CycloneDX: component external references (PURL), component CPEs
//
// "Unique" here means globally identifying, i.e. usable as a lookup key against
// a vulnerability database. It does not mean "not duplicated within the
// document", and NTIA asks nothing about intra-document distinctness. This
// previously counted components with a non-empty bom-ref/SPDXID, which is a
// document-local handle unrelated to the element, and so disagreed with the
// list command, the v2 NTIA profile and the BSI checks that share this key.
func compWithUniqIDCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withIDs := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetPurls()) > 0 || len(c.GetCpes()) > 0
	})

	s.setScore((float64(withIDs) / float64(totalComponents)) * 10.0)
	s.setDesc(fmt.Sprintf("%d/%d have unique ID's", withIDs, totalComponents))
	return *s
}

func sbomWithDepedenciesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	var totalDependencies int
	primary := d.PrimaryComp()

	if primary.IsPresent() {
		totalDependencies = len(d.GetDirectDependencies(primary.GetID()))

	}

	if totalDependencies > 0 {
		s.setScore(10.0)
	}

	s.setDesc(fmt.Sprintf("primary comp has %d dependencies ", totalDependencies))
	return *s
}

func sbomWithAuthorsCheck(d sbom.Document, c *check) score {
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

func sbomWithTimeStampCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	timestamp := d.Spec().GetCreationTimestamp()

	if timestamp != "" {
		if _, isTimeCorrect := common.CheckTimestamp(timestamp); isTimeCorrect {
			s.setScore(10.0)
			s.setDesc(fmt.Sprintf("doc has creation timestamp %s", d.Spec().GetCreationTimestamp()))
		} else {
			s.setScore(0.0)
			s.setDesc(fmt.Sprintf("doc has creation timestamp %s, but it is not in correct format", timestamp))
		}
	}
	return *s
}
