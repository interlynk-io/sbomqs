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
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// Components no longer maintained or declared end-of-life
func CompWithEOSOrEOL(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

// Components tagged as malicious in threat databases
func CompWithMalicious(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

// Components with Exploit Prediction Scoring System > 0.8
func CompWithHighEPSS(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

// Components with vulnerabilities in CISA's Known Exploited Vulns
func CompWithVulnSeverityCritical(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

func CompWithKev(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

func CompWithPurlValid(doc sbom.Document) catalog.ComprFeatScore {
	return formulae.ScoreCompNAA()
}

func CompWithCpeValid(doc sbom.Document) catalog.ComprFeatScore{
	return  formulae.ScoreCompNAA()
}
