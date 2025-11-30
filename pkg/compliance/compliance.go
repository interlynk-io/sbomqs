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
	"fmt"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/fsct"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// Report type constants define the supported compliance frameworks.
// These constants are used to specify which compliance standard to evaluate
// SBOM documents against.
//nolint:revive,stylecheck
const (
	// BSI_REPORT represents the German Federal Office for Information Security (BSI)
	// SBOM compliance framework.
	BSI_REPORT    = "BSI"
	// BSI_V2_REPORT represents version 2 of the BSI compliance framework.
	BSI_V2_REPORT = "BSI-V2"
	// NTIA_REPORT represents the NTIA (National Telecommunications and Information
	// Administration) minimum elements compliance framework.
	NTIA_REPORT   = "NTIA"
	// OCT_TELCO represents the OpenChain Telco SBOM compliance framework
	// specifically for telecommunications industry requirements.
	OCT_TELCO     = "OCT"
	// FSCT_V3 represents version 3 of the FSCT (FinTech Supply Chain Transparency)
	// compliance framework.
	FSCT_V3       = "FSCT"
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
//nolint:revive,stylecheck
func ComplianceResult(ctx context.Context, doc sbom.Document, reportType, fileName, outFormat string, coloredOutput bool) error {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ComplianceResult()")

	if !validReportTypes()[reportType] {
		log.Debugf("Invalid report type: %s\n", reportType)
		return errors.New("invalid report type")
	}

	if doc == nil {
		log.Debugf("sbom document is nil\n")
		return errors.New("sbom document is nil")
	}

	if fileName == "" {
		log.Debugf("file name is empty\n")
		return errors.New("file name is empty")
	}

	if outFormat == "" {
		log.Debugf("output format is empty\n")
		return errors.New("output format is empty")
	}

	switch {
	case reportType == BSI_REPORT:
		bsiResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == BSI_V2_REPORT:
		bsiV2Result(ctx, doc, fileName, outFormat)

	case reportType == NTIA_REPORT:
		ntiaResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == OCT_TELCO:
		if doc.Spec().GetSpecType() != pkgcommon.FormatSPDX {
			fmt.Println("The Provided SBOM spec is other than SPDX. Open Chain Telco only support SPDX specs SBOMs.")
			return nil
		}
		octResult(ctx, doc, fileName, outFormat, coloredOutput)

	case reportType == FSCT_V3:
		fsct.Result(ctx, doc, fileName, outFormat, coloredOutput)

	default:
		fmt.Println("No compliance type is provided")

	}

	return nil
}
