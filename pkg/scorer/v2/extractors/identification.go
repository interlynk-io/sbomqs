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
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/engine"
	"github.com/samber/lo"
)

// CompWithName: percentage of components that have a non-empty name.
func CompWithName(doc sbom.Document) config.FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return config.FeatureScore{
			Score:  engine.PerComponentScore(0, total),
			Desc:   "N/A (no components)",
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	return config.FeatureScore{
		Score:  engine.PerComponentScore(have, total),
		Desc:   fmt.Sprintf("%d/%d have names", have, total),
		Ignore: false,
	}
}

// CompWithVersion: percentage of components that have a non-empty version.
func CompWithVersion(doc sbom.Document) config.FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return config.FeatureScore{
			Score:  engine.PerComponentScore(0, total),
			Desc:   "N/A (no components)",
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	return config.FeatureScore{
		Score:  engine.PerComponentScore(have, total),
		Desc:   fmt.Sprintf("%d/%d have versions", have, total),
		Ignore: false,
	}
}

// CompWithUniqIDs: percentage of components whose ID is present and unique within the SBOM.
func CompWithUniqLocalIDs(doc sbom.Document) config.FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return config.FeatureScore{
			Score:  engine.PerComponentScore(0, total),
			Desc:   "N/A (no components)",
			Ignore: true,
		}
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		// cross-check: is this local unique id or unique id like purl, cpe ?
		if c.GetID() == "" {
			fmt.Println("c.GetID(): ", c.GetID())
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return config.FeatureScore{
		Score:  engine.PerComponentScore(len(have), total),
		Desc:   fmt.Sprintf("%d/%d have unique IDs", len(have), total),
		Ignore: false,
	}
}
