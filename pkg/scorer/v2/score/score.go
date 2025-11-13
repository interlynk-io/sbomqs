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

package score

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/comprehenssive"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

// ScoreSBOM scores a SBOM for profile or comprehenssive scoring.
// returns successful scoring results
func ScoreSBOM(ctx context.Context, cfg config.Config, paths []string) ([]api.Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Running ScoreSBOM: to score a SBOM")

	// 1. Validate paths
	validPaths := validateAndExpandPaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// 2) Initialize the catalog (features, categories, profiles) once.
	catal, err := registry.InitializeCatalog(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize catalog: %w", err)
	}

	// // 3) validate config
	// if err := validateConfig(ctx, catal, &cfg); err != nil {
	// 	return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	// }

	results := make([]api.Result, 0, len(validPaths))
	processed := 0

	for _, p := range validPaths {
		res, err := scoreOnePath(ctx, catal, cfg, p)
		if err != nil {
			log.Warnf("skip %s: %v", p, err)
			continue
		}
		results = append(results, res)
		processed++
	}

	if processed == 0 {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}
	return results, nil
}

// scoreOnePath opens a local file or downloads a URL, parses it into a document,
// and then evaluates each SBOM, and returns the single SBOM scoring result
func scoreOnePath(ctx context.Context, catalog *catalog.Catalog, cfg config.Config, path string) (api.Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Starting scoreOnePath: to score one by one")

	file, doc, err := openAndParse(ctx, cfg, path)
	if err != nil {
		return api.Result{}, err
	}
	defer file.Close()

	res, err := SBOMEvaluation(ctx, catalog, cfg, doc)
	res.Meta.Filename = path

	return res, err
}

// openAndParse normalizes the path (file or URL), extracts the signature,
// opens/creates a file handle, and constructs an sbom.Document
// and return file handle, sbom document
func openAndParse(ctx context.Context, cfg config.Config, path string) (*os.File, sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debugf("processing openAndParse...")

	var f *os.File
	var err error

	if utils.IsURL(path) {
		f, err = ProcessURLPath(ctx, cfg, path)
		if err != nil {
			return nil, nil, fmt.Errorf("process URL: %s: %w", path, err)
		}
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open file for reading: %q: %w", path, err)
		}
	}

	sig, err := ExtractSignature(ctx, cfg, f.Name())
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("get signature for %q: %w", path, err)
	}

	doc, err := sbom.NewSBOMDocument(ctx, f, sig)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("parse error for %q: %w", path, err)
	}

	return f, doc, nil
}

// SBOMEvaluation decides between profile-based and comprehensive scoring,
// delegates to a focused helper, and returns a single SBOM scoring result.
func SBOMEvaluation(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Starting SBOM Evaluation")

	if catal.Profiles != nil {
		log.Debugf("profile is provided")
		return evaluateProfiles(ctx, catal, doc)
	}

	return evaluateComprehensive(ctx, catal, cfg, doc)
}

// evaluateProfiles computes profile-based results for the given SBOM document.
// It resolves profile keys from cfg.Profile, evaluates them via the catalog,
// fills the result (score, grade, and per-profile results), and returns it.
func evaluateProfiles(ctx context.Context, catal *catalog.Catalog, doc sbom.Document) (api.Result, error) {
	log := logger.FromContext(ctx)

	log.Debugf("evaluate profiles")
	result := api.NewResult(doc)

	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
		for _, pk := range catal.Profiles {
			if pk.Key == registry.ProfileOCT {
				fmt.Println("OCT Profiles doesn't support for Cyclonedx SBOM")
				os.Exit(0)
			}
		}
	}

	// Evaluate all profiles and get the results
	profResults := profiles.Evaluate(ctx, catal, doc)

	result.InterlynkScore = formulae.ComputeInterlynkProfScore(profResults)
	result.Grade = formulae.ToGrade(result.InterlynkScore)
	result.Profiles = &profResults

	return *result, nil
}

func evaluateComprehensive(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	// Comprehensive Scoring
	log := logger.FromContext(ctx)
	log.Debugf("evaluating comprehenssive scoring")

	result := api.NewResult(doc)

	comprResult := comprehenssive.Evaluate(ctx, catal, doc)
	result.Comprehensive = &comprResult

	result.InterlynkScore = formulae.ComputeInterlynkComprScore(comprResult.CatResult)
	result.Grade = formulae.ToGrade(result.InterlynkScore)

	return *result, nil
}
