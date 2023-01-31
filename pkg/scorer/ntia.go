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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func compSupplierScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(compSupplierName))

	totalComponents := len(d.Components())
	withNames := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		return c.SupplierName() != ""
	})

	if totalComponents > 0 {
		s.setScore((float64(withNames) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have supplier names", withNames, totalComponents))

	return *s
}

func compWithNameScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(compWithNames))
	totalComponents := len(d.Components())
	withNames := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		return c.Name() != ""
	})
	if totalComponents > 0 {
		s.setScore((float64(withNames) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have names", withNames, totalComponents))

	return *s
}

func compWithVersionScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(compWithVersion))
	totalComponents := len(d.Components())

	withVersions := lo.CountBy(d.Components(), func(c sbom.Component) bool {
		return c.Version() != ""
	})
	if totalComponents > 0 {
		s.setScore((float64(withVersions) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have versions", withVersions, totalComponents))

	return *s
}

func compWithUniqIDScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(compWithUniqID))
	totalComponents := len(d.Components())

	withCpe := lo.FilterMap(d.Components(), func(c sbom.Component, _ int) (string, bool) {
		if len(c.Cpes()) > 0 {
			return c.Name(), true
		}
		return c.Name(), false
	})
	withPurl := lo.FilterMap(d.Components(), func(c sbom.Component, _ int) (string, bool) {
		if len(c.Purls()) > 0 {
			return c.Name(), true
		}
		return c.Name(), false
	})

	compWithIDs := append(withCpe, withPurl...)

	uniqComps := lo.Uniq(compWithIDs)

	if totalComponents > 0 {
		s.setScore((float64(len(uniqComps)) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have unique ID's", len(uniqComps), totalComponents))
	return *s
}

func docWithDepedenciesScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(docWithRelations))
	withRelations := len(d.Relations())
	if withRelations > 0 {
		s.setScore(10.0)
	}
	s.setDesc(fmt.Sprintf("doc has %d relationships ", withRelations))
	return *s
}

func docWithAuthorsScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(docWithAuthors))

	noOfAuthors := len(d.Authors())
	noOfTools := len(d.Tools())

	totalAuthors := noOfAuthors + noOfTools

	if totalAuthors > 0 {
		s.setScore(10.0)
	}
	s.setDesc(fmt.Sprintf("doc has %d authors", totalAuthors))

	return *s

}

func docWithTimeStampScore(d sbom.Document) score {
	s := newScore(CategoryNTIAMiniumElements, string(docWithTimestamp))

	if d.Spec().CreationTimestamp() != "" {
		s.setScore(10.0)
	}

	s.setDesc(fmt.Sprintf("doc has creation timestamp %s", d.Spec().CreationTimestamp()))
	return *s
}
