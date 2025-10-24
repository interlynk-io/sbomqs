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

package profiles

import (
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

func compWithSupplierCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.Suppliers().IsPresent()
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func compWithNameCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetName() != ""
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func compWithVersionCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetVersion() != ""
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

func compWithUniqIDCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{d.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	// uniqComps := lo.Uniq(compIDs)

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(len(have), len(comps)),
		Desc:   formulae.CompDescription(len(have), len(comps), "names"),
		Ignore: false,
	}
}

func sbomWithDepedenciesCheck(doc sbom.Document) ProfileFeatureScore {
	var have int
	if doc.PrimaryComp() != nil {
		have = doc.PrimaryComp().GetTotalNoOfDependencies()
	}

	return ProfileFeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("primary comp has %d dependencies", have),
		Ignore: false,
	}
}

func sbomWithAuthorsCheck(doc sbom.Document) ProfileFeatureScore {
	total := len(doc.Authors())

	if total == 0 {
		return ProfileFeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "0 authors",
			Ignore: false,
		}
	}

	return ProfileFeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("%d authors", total),
		Ignore: false,
	}
}

func sbomWithTimeStampCheck(doc sbom.Document) ProfileFeatureScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return ProfileFeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("timestamp"),
			Ignore: false,
		}
	}

	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return ProfileFeatureScore{
				Score:  formulae.BooleanScore(false),
				Desc:   fmt.Sprintf("invalid timestamp: %s", ts),
				Ignore: false,
			}
		}
	}

	return ProfileFeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   ts,
		Ignore: false,
	}
}
