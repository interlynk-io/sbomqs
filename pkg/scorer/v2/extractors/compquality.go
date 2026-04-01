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

// Component Quality category extractors.
// When the caller populates input.ComponentQuality (i.e. --url was provided and
// the API call succeeded), these functions score each feature based on findings
// returned by /api/v1/doctor/check. Without it they return N/A (informational).
package extractors

import (
	"context"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/interlynkapi"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
)

// CompWithEOSOrEOL: components no longer maintained or declared end-of-life.
// Maps to findings with domain "lifecycle" or check_code prefix "EOL-"/"EOS-".
func CompWithEOSOrEOL(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return f.Domain == "lifecycle" ||
			strings.HasPrefix(f.CheckCode, "EOL-") ||
			strings.HasPrefix(f.CheckCode, "EOS-")
	}, "components are maintained")
}

// CompWithMalicious: components tagged as malicious in threat databases.
// Maps to findings with domain "malicious" or check_code prefix "MAL-".
func CompWithMalicious(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return f.Domain == "malicious" ||
			strings.HasPrefix(f.CheckCode, "MAL-")
	}, "components are not malicious")
}

// CompWithHighEPSS: components with Exploit Prediction Scoring System > 0.8.
// Maps to findings with domain "epss" or check_code prefix "EPSS-".
func CompWithHighEPSS(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return f.Domain == "epss" ||
			strings.HasPrefix(f.CheckCode, "EPSS-")
	}, "components have low EPSS scores")
}

// CompWithVulnSeverityCritical: components with vulnerabilities in CISA's Known Exploited Vulns.
// Maps to findings with severity "critical".
func CompWithVulnSeverityCritical(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return f.Severity == "critical"
	}, "components have no critical vulnerabilities")
}

// CompWithKev: components which are actively exploited (CISA KEV).
// Maps to findings with domain "kev" or check_code prefix "KEV-".
func CompWithKev(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return f.Domain == "kev" ||
			strings.HasPrefix(f.CheckCode, "KEV-")
	}, "components are not in CISA KEV")
}

// CompWithPurlValid: component purl resolves to a package manager or repository.
// Maps to findings with check_code prefix "IDT-PURL-".
func CompWithPurlValid(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return strings.HasPrefix(f.CheckCode, "IDT-PURL-")
	}, "PURLs are valid")
}

// CompWithCpeValid: component CPE is found in NVD CPE database.
// Maps to findings with check_code prefix "IDT-CPE-".
func CompWithCpeValid(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	if input.ComponentQuality == nil {
		return formulae.ScoreCompNAA()
	}
	return scoreByFindings(input.ComponentQuality, func(f interlynkapi.Finding) bool {
		return strings.HasPrefix(f.CheckCode, "IDT-CPE-")
	}, "CPEs are valid")
}

// scoreByFindings counts how many components have no matching findings.
// Score = 10 * (passing / total). A component is "affected" if it has at
// least one finding that the predicate matches.
func scoreByFindings(r *interlynkapi.ComponentQualityResult, match func(interlynkapi.Finding) bool, label string) catalog.ComprFeatScore {
	total := r.TotalComponents
	if total == 0 {
		return formulae.ScoreCompNA()
	}

	affected := 0
	for _, findings := range r.FindingsByCompIndex {
		for _, f := range findings {
			if match(f) {
				affected++
				break // count each component at most once
			}
		}
	}

	passing := total - affected
	return formulae.ScoreCompFull(passing, total, label, false)
}
