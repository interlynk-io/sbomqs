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

package policy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

func Engine(ctx context.Context, policyConfig *Params, policies []Policy) error {
	log := logger.FromContext(ctx)
	log.Debugf("Starting Engine...")

	// Load SBOM File
	f, err := os.Open(policyConfig.SBOMFile)
	if err != nil {
		return fmt.Errorf("failed to open input %s: %w", policyConfig.SBOMFile, err)
	}
	log.Debugf("open SBOM file")

	// Parse SBOM
	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		return fmt.Errorf("failed to load SBOM: %w", err)
	}
	log.Debugf("SBOM is parsed")

	// Create extractor: for quick mapping
	fieldExtractor := NewExtractor(doc)
	fieldExtractor.MapFieldWithFunction(ctx)

	log.Debugf("field mapping done via extractor")

	log.Debugf("Evaluation of policy against SBOM begins...")

	// Pre-allocate policy results slice with known capacity
	policyResults := make([]PolicyResult, 0, len(policies))

	// Evaluate policies
	for _, policy := range policies {
		log.Debugf("Evaluating policy: ", policy.Name)

		// evaluate each policy one by one against SBOM
		result, err := EvaluatePolicyAgainstSBOMs(ctx, policy, doc, fieldExtractor)
		if err != nil {
			return fmt.Errorf("policy %s evaluation failed: %w", policy.Name, err)
		}
		policyResults = append(policyResults, result)
	}

	// Reporting
	switch strings.ToLower(policyConfig.OutputFmt) {
	case "json":
		if err := ReportJSON(ctx, policyResults); err != nil {
			return fmt.Errorf("failed to write json output: %w", err)
		}
	case "table":
		if err := ReportTable(ctx, policyResults); err != nil {
			return fmt.Errorf("failed to write yaml output: %w", err)
		}
	default:
		if err := ReportBasic(ctx, policyResults); err != nil {
			return fmt.Errorf("failed to write table output: %w", err)
		}
	}

	return nil
}
