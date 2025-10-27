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
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// CompWithSHA1Plus returns coverage of components that have SHA-1 or stronger
// (SHA-1, SHA-256, SHA-384, or SHA-512).
func CompWithSHA1Plus(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreNA()
	}

	have := 0
	for _, comp := range comps {
		if hasSHA1Plus(comp) {
			have++
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "SHA-1+"),
		Ignore: false,
	}
}

// CompWithSHA256Plus returns coverage of components that have SHA-256 or stronger.
func CompWithSHA256Plus(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreNA()
	}

	have := 0
	for _, c := range comps {
		if hasSHA256Plus(c) {
			have++
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "SHA-256+"),
		Ignore: false,
	}
}

// allow tests to stub this
var verifySignature = common.VerifySignature

// SBOMSignature verifies a doc-level signature if a bundle is present.
// Scoring:
//
//	10 = signature present and verification succeeded
//	 5 = signature present but verification failed
//	 0 = no signature / incomplete bundle
func SBOMSignature(doc sbom.Document) catalog.ComprFeatScore {
	sig := doc.Signature()
	if sig == nil {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   formulae.MissingField("signature"),
			Ignore: false,
		}
	}

	pubKeyPath := strings.TrimSpace(sig.GetPublicKey())
	blobPath := strings.TrimSpace(sig.GetBlob())
	sigPath := strings.TrimSpace(sig.GetSigValue())

	// Incomplete bundle → treat as missing
	if pubKeyPath == "" || blobPath == "" || sigPath == "" {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   "signature bundle incomplete",
			Ignore: false,
		}
	}

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return catalog.ComprFeatScore{
			Score:  5, // bundle present, but verification cannot succeed
			Desc:   fmt.Sprintf("cannot read public key: %v", err),
			Ignore: false,
		}
	}

	ok, err := verifySignature(pubKeyBytes, blobPath, sigPath)
	if err != nil {
		return catalog.ComprFeatScore{
			Score:  5,
			Desc:   "signature present but verification failed",
			Ignore: false,
		}
	}
	if ok {
		return catalog.ComprFeatScore{
			Score:  10,
			Desc:   "signature verification succeeded",
			Ignore: false,
		}
	}
	return catalog.ComprFeatScore{
		Score:  5,
		Desc:   "signature present but invalid",
		Ignore: false,
	}
}

func hasSHA1Plus(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		if isSHA1Plus(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA1Plus(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA1", "SHA256", "SHA384", "SHA512":
		return true
	default:
		return false
	}
}

func hasSHA256Plus(c sbom.GetComponent) bool {
	for _, ch := range c.GetChecksums() {
		if isSHA256Plus(ch.GetAlgo()) && strings.TrimSpace(ch.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA256Plus(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA256", "SHA384", "SHA512":
		return true
	default:
		return false
	}
}
