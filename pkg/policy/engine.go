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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func Engine(ctx context.Context, policyConfig *Params, policies []Policy) error {
	//
	log := logger.FromContext(ctx)
	log.Debugf("Starting Engine...")

	f, err := os.Open(policyConfig.SBOMFile)
	if err != nil {
		return fmt.Errorf("failed to open input %s: %w", policyConfig.SBOMFile, err)
	}

	// Parse SBOM
	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		return fmt.Errorf("failed to load SBOM: %w", err)
	}

	// Create extractor
	fieldExtractor := NewExtractor(doc)

	// Evaluate policies
	var results []Result
	for _, p := range policies {
		result, err := EvalPolicy(ctx, p, doc, fieldExtractor)
		if err != nil {
			return fmt.Errorf("policy %s evaluation failed: %w", p.Name, err)
		}
		results = append(results, result)
	}

	// Reporting
	switch strings.ToLower(policyConfig.OutputFmt) {
	case "json":
		if err := ReportJSON(os.Stdout, results); err != nil {
			return fmt.Errorf("failed to write json output: %w", err)
		}
	case "yaml":
		if err := ReportYAML(os.Stdout, results); err != nil {
			return fmt.Errorf("failed to write yaml output: %w", err)
		}
	default:
		if err := ReportTable(os.Stdout, results); err != nil {
			return fmt.Errorf("failed to write table output: %w", err)
		}
	}

	return nil
}
