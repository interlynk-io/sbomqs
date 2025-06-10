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

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validSpdxVersion     = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

// specCheck checks for spdx or cyclonedx
func bsiSpecCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	version := d.Spec().GetVersion()
	spec := d.Spec().GetSpecType()

	if spec == "spdx" {
		count := lo.Count(validBsiSpdxVersions, version)
		if count > 0 {
			s.setScore(10.0)
			s.setDesc(fmt.Sprintf("provided sbom spec: %s, and version: %s is supported", spec, version))
		} else {
			s.setScore(5.0)
			s.setDesc(fmt.Sprintf("provided sbom spec: %s, is supported but not version: %s", spec, version))
		}
	} else if spec == "cyclonedx" {
		count := lo.Count(validBsiCdxVersions, version)
		if count > 0 {
			s.setScore(10.0)
			s.setDesc(fmt.Sprintf("provided sbom spec %s, and version %s is supported", spec, version))
		} else {
			s.setScore(5.0)
			s.setDesc(fmt.Sprintf("provided sbom spec %s, is supported but not version %s", spec, version))
		}
	}

	return *s
}

func docWithURICheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if doc.Spec().GetURI() == "" {
		s.setDesc(fmt.Sprintf("doc has no URI "))
		s.setScore(0.0)
	} else {
		s.setDesc(fmt.Sprintf("doc has URI "))
		s.setScore(10.0)
	}

	return *s
}

func bsiCompWithUniqIDCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	compIDs := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		purl := c.GetPurls()
		cpes := c.GetCpes()

		return len(purl) > 0 || len(cpes) > 0
	})

	if totalComponents > 0 {
		s.setScore((float64(compIDs) / float64(totalComponents)) * 10.0)
	}
	s.setDesc(fmt.Sprintf("%d/%d have unique ID's", compIDs, totalComponents))
	return *s
}

func bsiCompWithLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.Licenses())
	})

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have compliant licenses", withLicenses, totalComponents))

	return *s
}

func bsiCompWithChecksumsCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withChecksums := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return lo.ContainsBy(c.GetChecksums(), func(checksum sbom.GetChecksum) bool {
			return lo.Contains(algos, checksum.GetAlgo())
		})
	})

	if totalComponents > 0 {
		s.setScore((float64(withChecksums) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have checksums", withChecksums, totalComponents))

	return *s
}

func compWithSourceCodeURICheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if d.Spec().GetSpecType() == "spdx" {
		s.setScore(0.0)
		s.setDesc("no-deterministic-field in spdx")
		s.setIgnore(true)
		return *s
	}

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withSourceCodeURI := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.SourceCodeURL() != ""
	})

	if totalComponents > 0 {
		s.setScore((float64(withSourceCodeURI) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have source code URI", withSourceCodeURI, totalComponents))
	return *s
}

func compWithExecutableURICheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withExecutableURI := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.GetDownloadLocationURL() != ""
	})

	if totalComponents > 0 {
		s.setScore((float64(withExecutableURI) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have executable URI", withExecutableURI, totalComponents))
	return *s
}

func compWithSourceCodeHashCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if d.Spec().GetSpecType() == "cyclonedx" {
		s.setScore(0.0)
		s.setDesc("no-deterministic-field in cdx")
		s.setIgnore(true)
		return *s
	}

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withSourceCodeHash := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.SourceCodeHash() != ""
	})

	if totalComponents > 0 {
		s.setScore((float64(withSourceCodeHash) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have source code hash", withSourceCodeHash, totalComponents))
	return *s
}
