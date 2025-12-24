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

// Package engine provides the core execution engine for sbomqs operations,
// including compliance checking, scoring, and report generation functionality.
package engine

import (
	"context"
	"errors"
	"os"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/spf13/afero"
	"go.uber.org/zap"
)

func ComplianceRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)

	log.Info("Starting compliance run",
		zap.Strings("paths", ep.Path),
	)

	if len(ep.Path) == 0 {
		log.Error("Compliance run failed: input path missing")
		return errors.New("path is required")
	}

	log.Debug("Compliance configuration resolved",
		zap.Bool("bsi", ep.Bsi),
		zap.Bool("bsi_v2", ep.BsiV2),
		zap.Bool("oct", ep.Oct),
		zap.Bool("fsct", ep.Fsct),
		zap.Bool("basic", ep.Basic),
		zap.Bool("json", ep.JSON),
		zap.Bool("color", ep.Color),
	)

	log.Debug("Loading SBOM document", zap.String("path", ep.Path[0]))
	doc, err := getSbomDocument(ctx, ep)
	if err != nil {
		log.Error("Failed to load SBOM document", zap.String("path", ep.Path[0]), zap.Error(err))
	}

	var reportType string

	switch {
	case ep.Bsi:
		reportType = "BSI"
	case ep.BsiV2:
		reportType = "BSI-V2"
	case ep.Oct:
		reportType = "OCT"
	case ep.Fsct:
		reportType = "FSCT"
	default:
		reportType = "NTIA"
	}

	log.Debug("Compliance report type selected", zap.String("report_type", reportType))

	var outFormat string

	switch {
	case ep.Basic:
		outFormat = pkgcommon.ReportBasic
	case ep.JSON:
		outFormat = pkgcommon.FormatJSON
	default:
		outFormat = pkgcommon.ReportDetailed
	}

	coloredOutput := ep.Color

	log.Debug("Output format selected", zap.String("format", outFormat), zap.Bool("colored", coloredOutput))

	err = compliance.ComplianceResult(ctx, *doc, reportType, ep.Path[0], outFormat, coloredOutput)
	if err != nil {
		log.Error("Compliance check failed",
			zap.String("path", ep.Path[0]),
			zap.String("report_type", reportType),
			zap.Error(err),
		)
		return err
	}

	log.Info("Compliance report generated successfully",
		zap.String("path", ep.Path[0]),
		zap.String("report_type", reportType),
		zap.String("format", outFormat),
	)
	return nil
}

func getSbomDocument(ctx context.Context, ep *Params) (*sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debug("Resolving SBOM document",
		zap.String("path", ep.Path[0]),
	)

	path := ep.Path[0]

	log.Debug("Fetching signature bundle",
		zap.String("path", path),
	)

	_, signature, publicKey, err := common.GetSignatureBundle(ctx, path, "", "")
	if err != nil {
		log.Error("Failed to fetch signature bundle",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, err
	}

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
	}
	var doc sbom.Document

	log.Debug("SBOM source resolved",
		zap.String("path", path),
		zap.Bool("is_url", IsURL(path)),
	)

	if IsURL(path) {
		log.Info("Processing SBOM from URL", zap.String("url", path))
		url, sbomFilePath := path, path
		var err error

		if IsGit(url) {
			log.Debug("Detected Git-based SBOM URL", zap.String("url", path))
			sbomFilePath, url, err = handleURL(path)
			if err != nil {
				log.Error("Failed to resolve SBOM URL", zap.String("url", path), zap.Error(err))
			}
			return nil, err
		}
		fs := afero.NewMemMapFs()

		file, err := fs.Create(sbomFilePath)
		if err != nil {
			return nil, err
		}

		f, err := ProcessURL(url, file)
		if err != nil {
			return nil, err
		}

		log.Debug("Parsing SBOM document", zap.String("path", path))
		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Error("Failed to parse SBOM document", zap.String("path", path), zap.Error(err))
			return nil, err
		}

	} else {
		log.Debug("Validating SBOM file path", zap.String("path", path))
		if _, err := os.Stat(path); err != nil {
			log.Error("SBOM file not accessible", zap.String("path", path), zap.Error(err))
			return nil, err
		}

		log.Debug("Opening SBOM file", zap.String("path", path))
		// #nosec G304 -- User-provided paths are expected for CLI tool
		f, err := os.Open(path)
		if err != nil {
			log.Error("Failed to open SBOM file", zap.String("path", path), zap.Error(err))
			return nil, err
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Warn("failed to close file", zap.Error(err))
			}
		}()

		log.Debug("Parsing SBOM document", zap.String("path", path))
		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Error("Failed to parse SBOM document", zap.String("path", path), zap.Error(err))
			return nil, err
		}
	}

	return &doc, nil
}
