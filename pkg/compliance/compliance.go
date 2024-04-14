// Copyright 2024 Interlynk.io
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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

const CRA_REPORT = "CRA"
const NTIA_REPORT = "NTIA"

func ComplianceResult(ctx context.Context, doc sbom.Document, reportType, fileName, outFormat string) error {
	log := logger.FromContext(ctx)
	log.Debug("compliance.ComplianceResult()")

	if reportType != CRA_REPORT && reportType != NTIA_REPORT {
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

	if reportType == CRA_REPORT {
		craResult(ctx, doc, fileName, outFormat)
	}

	if reportType == NTIA_REPORT {
		ntiaResult(ctx, doc, fileName, outFormat)
	}

	return nil
}
