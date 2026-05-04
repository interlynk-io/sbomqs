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

package interlynkapi

import (
	"context"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"go.uber.org/zap"
)

// buildPayloads converts all SBOM components into the slice of ComponentPayload
// that the API expects. Each component is mapped independently via mapComponent.
func buildPayloads(ctx context.Context, comps []sbom.GetComponent) []ComponentPayload {
	log := logger.FromContext(ctx)

	log.Debug("Building API payloads from SBOM components",
		zap.Int("component_count", len(comps)),
	)

	payloads := make([]ComponentPayload, len(comps))
	purlCount := 0
	cpeCount := 0
	licenseCount := 0

	for i, comp := range comps {
		payloads[i] = mapComponent(comp)
		if payloads[i].Purl != nil {
			purlCount++
		}
		cpeCount += len(payloads[i].Cpes)
		if payloads[i].License != nil {
			licenseCount++
		}
	}

	log.Debug("Completed building API payloads",
		zap.Int("payload_count", len(payloads)),
		zap.Int("with_purl", purlCount),
		zap.Int("total_cpes", cpeCount),
		zap.Int("with_license", licenseCount),
	)

	return payloads
}

// mapComponent converts a single sbom.GetComponent to the API payload format.
// Only the first PURL and first license are sent; CPEs are sent as strings.
func mapComponent(c sbom.GetComponent) ComponentPayload {

	p := ComponentPayload{
		Name:    strings.TrimSpace(c.GetName()),
		Version: strings.TrimSpace(c.GetVersion()),
		Cpes:    []string{},
	}

	// First PURL
	if purls := c.GetPurls(); len(purls) > 0 {
		s := purls[0].String()
		p.Purl = &s
	}

	// All CPEs as strings
	for _, cpe := range c.GetCpes() {
		if s := strings.TrimSpace(cpe.String()); s != "" {
			p.Cpes = append(p.Cpes, s)
		}
	}

	// First license expression
	if lics := c.GetLicenses(); len(lics) > 0 {
		expr := strings.TrimSpace(lics[0].Name())
		if expr != "" {
			p.License = &expr
		}
	}

	return p
}
