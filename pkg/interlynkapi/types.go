// Copyright 2026 Interlynk.io
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

// Package interlynkapi provides a client for the Interlynk Component Quality API.
// When --url is provided to sbomqs score, components are extracted from the SBOM,
// POSTed to `/api/v1/doctor/check` in batches, and the resulting findings populate
// the Component Quality category instead of returning N/A.
package interlynkapi

// ComponentPayload is one component in the API request body.
type ComponentPayload struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Purl    *string  `json:"purl"`
	Cpes    []string `json:"cpes"`
	License *string  `json:"license"`
}

// DoctorRequest is the full POST body sent to /api/v1/doctor/check.
type DoctorRequest struct {
	Components []ComponentPayload `json:"components"`
}

// ComponentRef is the component summary echoed back inside each Finding.
type ComponentRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Finding represents one issue detected for a component.
type Finding struct {
	// Index is the zero-based position of the component in the batch request.
	Index       int          `json:"index"`
	Component   ComponentRef `json:"component"`
	CheckCode   string       `json:"check_code"`
	Domain      string       `json:"domain"`
	Severity    string       `json:"severity"` // Severity is one of: critical, high, medium, low
	Message     string       `json:"message"`
	AutoFixable bool         `json:"auto_fixable"`
}

// BySeverity holds per-severity finding counts.
type BySeverity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Summary is the top-level summary block in the API response.
type Summary struct {
	Total             int                   `json:"total"`
	BySeverity        BySeverity            `json:"by_severity"`
	ByDomain          map[string]BySeverity `json:"by_domain"`
	ComponentsChecked int                   `json:"components_checked"`
}

// DoctorResponse is the full JSON body returned by /api/v1/doctor/check.
type DoctorResponse struct {
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
	Tier      string    `json:"tier"`
	ChecksRun []string  `json:"checks_run"`
}

// ComponentQualityResult holds the merged findings across all batches.
// FindingsByCompIndex maps the original (pre-batching) component index to
// all findings reported for that component.
type ComponentQualityResult struct {
	// FindingsByCompIndex maps original component index => findings.
	FindingsByCompIndex map[int][]Finding
	// TotalComponents is the total number of components sent to the API.
	TotalComponents int
	// Tier is the service tier returned by the last successful batch ("authenticated" | "unauthenticated").
	Tier string
}
