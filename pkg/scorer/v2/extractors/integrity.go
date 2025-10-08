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
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/engine"
	"github.com/samber/lo"
)

// comp_with_checksum: SHA-1 minimum
func CompWithCheckSumSHA_1(doc sbom.Document, component sbom.GetComponent) config.FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return config.FeatureScore{
			Score:  engine.PerComponentScore(0, total),
			Desc:   "N/A (no components)",
			Ignore: true,
		}
	}

	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}

	checksums := component.GetChecksums()
	for _, checksum := range checksums {
		if lo.Count(algos, checksum.GetAlgo()) > 0 {
			result = checksum.GetContent()
			score = 10.0
			break
		}
	}
}

// comp_with_checksum_sha256: SHA-256 or stronger algorithm

// sbom_signature
