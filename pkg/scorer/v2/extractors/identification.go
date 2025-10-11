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

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// CompWithName: percentage of components that have a non-empty name.
func CompWithName(doc sbom.Document) config.FeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	return config.FeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

// CompWithVersion: percentage of components that have a non-empty version.
func CompWithVersion(doc sbom.Document) config.FeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	return config.FeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "versions"),
		Ignore: false,
	}
}

// CompWithUniqIDs: percentage of components whose ID is present and unique within the SBOM.
func CompWithUniqLocalIDs(doc sbom.Document) config.FeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreNA()
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			fmt.Println("c.GetID(): ", c.GetID())
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return config.FeatureScore{
		Score:  formulae.PerComponentScore(len(have), len(comps)),
		Desc:   formulae.CompDescription(len(have), len(comps), "unique IDs"),
		Ignore: false,
	}
}
