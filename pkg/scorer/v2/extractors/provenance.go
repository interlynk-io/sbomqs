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
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/engine"
)

// SBOMCreationTime: document has a valid ISO-8601 timestamp (RFC3339/RFC3339Nano).
func SBOMCreationTimestamp(doc sbom.Document) config.FeatureScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return config.FeatureScore{
			Score:  engine.BooleanScore(false),
			Desc:   "missing timestamp",
			Ignore: false,
		}
	}

	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return config.FeatureScore{
			Score:  engine.BooleanScore(false),
			Desc:   fmt.Sprintf("invalid timestamp: %s", ts),
			Ignore: false,
		}
	}

	return config.FeatureScore{
		Score:  engine.BooleanScore(true),
		Desc:   ts,
		Ignore: false,
	}
}

// Creator.(Person/Organization):
func SBOMAuthors(doc sbom.Document) config.FeatureScore {
	total := len(doc.Authors())

	return config.FeatureScore{
		Score:  engine.BooleanScore(total > 0),
		Desc:   fmt.Sprintf("%d authors/tools", total),
		Ignore: false,
	}
}

// sbom_tool_version: Tool name and version present

// sbom_supplier (N/A for SPDX)

// sbom_namespace: namespace(SPDX) or (serialNumber + version)

// sbom_lifecycle (N/A for SPDX)
