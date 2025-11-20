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
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

// check whether provided spec is supported or not
// and also check provided spec version is supported or not wrt BSI spec
func specWithVersionCompliant(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	version := d.Spec().GetVersion()
	spec := d.Spec().GetSpecType()

	if spec == string(sbom.SBOMSpecSPDX) {
		count := lo.Count(validBsiSpdxVersions, version)
		if count > 0 {
			s.setScore(10.0)
			s.setDesc(fmt.Sprintf("provided sbom spec: %s, and version: %s is supported", spec, version))
		} else {
			s.setScore(5.0)
			s.setDesc(fmt.Sprintf("provided sbom spec: %s, is supported but not version: %s", spec, version))
		}
	} else if spec == string(sbom.SBOMSpecCDX) {
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

func sbomWithURICheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if doc.Spec().GetURI() == "" {
		s.setDesc("doc has no URI ")
		s.setScore(0.0)
	} else {
		s.setDesc("doc has URI ")
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

// check whether provided license is compliant or non-compliant
func compWithLicensesCompliantCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}
	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.GetLicenses())
	})

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have compliant licenses", withLicenses, totalComponents))

	return *s
}

func compWithDependencyCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withDependencies := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.HasRelationShips()
	})

	if totalComponents > 0 {
		s.setScore((float64(withDependencies) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have dependencies", withDependencies, totalComponents))

	return *s
}

// checks whether components have sha256 checksums
// this is a BSI requirement
func compWithSHA256ChecksumsCheck(d sbom.Document, c *check) score {
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
		return c.GetSourceCodeURL() != ""
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

func sbomWithBomLinksCheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	bom := doc.Spec().GetExtDocRef()
	if len(bom) == 0 {
		s.setScore(0.0)
		s.setDesc("no bom links found")
		// s.setIgnore(true)
		return *s
	}
	s.setScore(10.0)
	s.setDesc(fmt.Sprintf("found %d bom links", len(bom)))
	return *s
}

// v2.1
func sbomWithVulnCheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if doc.Spec().GetSpecType() == "spdx" {
		s.setScore(10.0)
		s.setDesc("no-deterministic-field in spdx")
		return *s
	}

	vulns := doc.Vulnerabilities()

	var allVulnIDs []string

	for _, v := range vulns {
		if vulnID := v.GetID(); vulnID != "" {
			allVulnIDs = append(allVulnIDs, vulnID)
		}
	}

	if len(allVulnIDs) > 0 {
		s.setScore(0.0)
		s.setDesc("vulnerabilities found" + strings.Join(allVulnIDs, ", "))
	} else {
		s.setScore(10.0)
		s.setDesc("no vulnerabilities found")
	}

	return *s
}

// docBuildProcessCheck
func sbomBuildLifecycleCheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if doc.Spec().GetSpecType() == "spdx" {
		s.setScore(0.0)
		s.setDesc("no-deterministic-field in spdx")
		s.setIgnore(true)
		return *s
	}

	lifecycles := doc.Lifecycles()

	found := lo.Count(lifecycles, "build")
	if found > 0 {
		s.setScore(10.0)
		s.setDesc("doc has build phase in lifecycle")
	} else {
		s.setScore(0.0)
		s.setDesc("doc has no build phase in lifecycle")
	}

	return *s
}

func sbomWithSignatureCheck(doc sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	if doc.Signature() != nil {
		// verify signature
		pubKey := doc.Signature().GetPublicKey()
		blob := doc.Signature().GetBlob()
		sig := doc.Signature().GetSigValue()

		pubKeyData, err := os.ReadFile(pubKey)
		if err != nil {
			s.setScore(0.0)
			s.setDesc("No signature or public key provided!")
			// s.setIgnore(true)
			return *s
		}

		valid, err := common.VerifySignature(pubKeyData, blob, sig)
		if err != nil {
			s.setScore(0.0)
			s.setDesc("Signature verification failed!")
			return *s
		}
		if valid {
			s.setScore(10.0)
			s.setDesc("Signature verification succeeded!")
		} else {
			s.setScore(5.0)
			s.setDesc("Signature provided but verification failed!")
		}
		common.RemoveFileIfExists("extracted_public_key.pem")
		common.RemoveFileIfExists("extracted_signature.bin")
		common.RemoveFileIfExists("standalone_sbom.json")
	} else {
		s.setScore(0.0)
		s.setDesc("No signature provided")
		s.setIgnore(true)
	}

	return *s
}

// compWithAssociatedLicensesCheck checks whether components have associated licenses
// this is a BSI requirement
func compWithAssociatedLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	var withLicenses int
	spec := d.Spec().GetSpecType()
	if spec == "spdx" {
		withLicenses = lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
			return common.AreLicensesValid(c.ConcludedLicenses())
		})
	} else if spec == "cyclonedx" {
		withLicenses = lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
			return common.AreLicensesValid(c.GetLicenses())
		})
	}

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have compliant licenses", withLicenses, totalComponents))

	return *s
}

// compWithConcludedLicensesCheck checks whether components have concluded licenses
// this is a BSI requirement
func compWithConcludedLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.ConcludedLicenses())
	})

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have compliant licenses", withLicenses, totalComponents))

	return *s
}

// compWithDeclaredLicensesCheck checks whether components have declared licenses
// this is a BSI requirement
func compWithDeclaredLicensesCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setScore(0.0)
		s.setDesc("N/A (no components)")
		s.setIgnore(true)
		return *s
	}

	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return common.AreLicensesValid(c.DeclaredLicenses())
	})

	if totalComponents > 0 {
		s.setScore((float64(withLicenses) / float64(totalComponents)) * 10.0)
	}

	s.setDesc(fmt.Sprintf("%d/%d have compliant licenses", withLicenses, totalComponents))

	return *s
}
