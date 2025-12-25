// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"context"
	"errors"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/fsct"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"go.uber.org/zap"
)

// Report type constants define the supported compliance frameworks.
// These constants are used to specify which compliance standard to evaluate
// SBOM documents against.
//
//nolint:revive,stylecheck
const (
	// BSI_REPORT represents the German Federal Office for Information Security (BSI)
	// SBOM compliance framework.
	BSI_REPORT = "BSI"
	// BSI_V2_REPORT represents version 2 of the BSI compliance framework.
	BSI_V2_REPORT = "BSI-V2"
	// NTIA_REPORT represents the NTIA (National Telecommunications and Information
	// Administration) minimum elements compliance framework.
	NTIA_REPORT = "NTIA"
	// OCT_TELCO represents the OpenChain Telco SBOM compliance framework
	// specifically for telecommunications industry requirements.
	OCT_TELCO = "OCT"
	// FSCT_V3 represents version 3 of the FSCT (FinTech Supply Chain Transparency)
	// compliance framework.
	FSCT_V3 = "FSCT"
)

func validReportTypes() map[string]bool {
	return map[string]bool{
		BSI_REPORT:    true,
		BSI_V2_REPORT: true,
		NTIA_REPORT:   true,
		OCT_TELCO:     true,
		FSCT_V3:       true,
	}
}

// ComplianceResult evaluates an SBOM document against the specified compliance framework
// and generates a compliance report in the requested format.
//
// Parameters:
//   - ctx: Context for logging and cancellation
//   - doc: The SBOM document to evaluate for compliance
//   - reportType: The compliance framework to evaluate against (use constants: BSI_REPORT, NTIA_REPORT, etc.)
//   - fileName: The name of the SBOM file being evaluated (used for reporting)
//   - outFormat: Output format for the report ("json", "basic", "detailed")
//   - coloredOutput: Whether to use colored output in detailed reports
//
// Returns an error if the inputs are invalid or evaluation fails.
// Supported report types: BSI, BSI-V2, NTIA, OCT (OpenChain Telco), and FSCT.
// Note: OCT compliance only supports SPDX format SBOM documents.
//
//nolint:revive,stylecheck
func ComplianceResult(ctx context.Context, doc sbom.Document, reportType, fileName, outFormat string, coloredOutput bool) error {
	log := logger.FromContext(ctx)
	log.Debug("Preparing compliance report",
		zap.String("report_type", reportType),
		zap.String("output_format", outFormat),
	)
	if !validReportTypes()[reportType] {
		log.Error("Invalid compliance report type",
			zap.String("report_type", reportType),
		)
		return errors.New("invalid report type")
	}

	if doc == nil {
		log.Debug("SBOM document is nil")
		return errors.New("sbom document is nil")
	}

	if fileName == "" {
		log.Debug("Output file name is empty")
		return errors.New("file name is empty")
	}

	if outFormat == "" {
		log.Debug("Output format is empty")
		return errors.New("output format is empty")
	}

	switch {
	case reportType == BSI_REPORT:
		log.Debug("Running BSI compliance report")
		bsiResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == BSI_V2_REPORT:
		log.Debug("Running BSI V2 compliance report")
		bsiV2Result(ctx, doc, fileName, outFormat)

	case reportType == NTIA_REPORT:
		log.Debug("Running NTIA compliance report")
		ntiaResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == OCT_TELCO:
		if doc.Spec().GetSpecType() != pkgcommon.FormatSPDX {
			log.Warn("OpenChain Telco report supports only SPDX SBOMs",
				zap.String("spec", doc.Spec().GetSpecType()),
			)
			return nil
		}
		log.Debug("Running OpenChain Telco compliance report")
		octResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == FSCT_V3:
		log.Debug("Running FSCT v3 compliance report")
		fsct.Result(ctx, doc, fileName, outFormat, coloredOutput)

	default:
		log.Warn("No compliance report generated",
			zap.String("report_type", reportType),
		)
	}

	return nil
}
