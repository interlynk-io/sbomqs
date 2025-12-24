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
	"go.uber.org/zap"
)

func Engine(ctx context.Context, policyConfig *Params, policies []Policy) error {
	log := logger.FromContext(ctx)
	log.Info("Starting policy evaluation",
		zap.String("sbom", policyConfig.SBOMFile),
		zap.Int("policies", len(policies)),
		zap.String("output_format", policyConfig.OutputFmt),
	)

	// Load SBOM File
	f, err := os.Open(policyConfig.SBOMFile)
	if err != nil {
		log.Error("Failed to open SBOM file",
			zap.String("sbom", policyConfig.SBOMFile),
			zap.Error(err),
		)
		return fmt.Errorf("failed to open input %s: %w", policyConfig.SBOMFile, err)
	}

	log.Debug("SBOM file opened successfully",
		zap.String("sbom", policyConfig.SBOMFile),
	)

	// Parse SBOM
	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		log.Error("Failed to parse SBOM document",
			zap.String("sbom", policyConfig.SBOMFile),
			zap.Error(err),
		)
		return fmt.Errorf("failed to load SBOM: %w", err)
	}
	log.Info("SBOM parsed successfully")

	// Create extractor: for quick mapping
	fieldExtractor := NewExtractor(doc)
	fieldExtractor.MapFieldWithFunction(ctx)

	log.Debug("SBOM fields mapped using extractor")

	// Pre-allocate policy results slice with known capacity
	policyResults := make([]PolicyResult, 0, len(policies))

	// Evaluate policies
	for _, policy := range policies {
		log.Debug("Evaluating policy",
			zap.String("policy", policy.Name),
		)
		// evaluate each policy one by one against SBOM
		result, err := EvaluatePolicyAgainstSBOMs(ctx, policy, doc, fieldExtractor)
		if err != nil {
			log.Error("Policy evaluation failed",
				zap.String("policy", policy.Name),
				zap.Error(err),
			)
			return fmt.Errorf("policy %s evaluation failed: %w", policy.Name, err)
		}
		policyResults = append(policyResults, result)
	}

	log.Info("Policy evaluation completed",
		zap.Int("evaluated", len(policyResults)),
	)

	// Reporting
	log.Info("Generating policy evaluation report",
		zap.String("format", policyConfig.OutputFmt),
	)

	switch strings.ToLower(policyConfig.OutputFmt) {
	case "json":
		if err := ReportJSON(ctx, policyResults); err != nil {
			log.Error("Failed to generate JSON report",
				zap.Error(err),
			)
			return fmt.Errorf("failed to write json output: %w", err)
		}
	case "table":
		if err := ReportTable(ctx, policyResults); err != nil {
			log.Error("Failed to generate table report",
				zap.Error(err),
			)
			return fmt.Errorf("failed to write yaml output: %w", err)
		}
	default:
		if err := ReportBasic(ctx, policyResults); err != nil {
			log.Error("Failed to generate basic report",
				zap.Error(err),
			)
			return fmt.Errorf("failed to write table output: %w", err)
		}
	}
	log.Info("Policy evaluation report generated successfully")

	return nil
}
