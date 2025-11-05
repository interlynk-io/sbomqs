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

	// 1. Validate paths
	validPaths := validateAndExpandPaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// 2) Initialize the catalog (features, categories, profiles) once.
	catalog := registry.InitializeCatalog()

	// 3) validate config
	if err := validateConfig(ctx, catalog, &cfg); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	results := make([]api.Result, 0, len(validPaths))
	processed := 0

	for _, p := range validPaths {
		res, err := scoreOnePath(ctx, catalog, cfg, p)
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
	log.Debugf("processing scoreOnePath")

	file, doc, err := openAndParse(ctx, cfg, path)
	if err != nil {
		return api.Result{}, err
	}
	defer file.Close()

	// if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
	// 	// Resolve profiles alias
	// 	profileKeys := catalog.ResolveProfileKeys(cfg.Profile)
	// 	if len(profileKeys) == 0 {
	// 		// return , fmt.Errorf("no valid profiles resolved from: %v", cfg.Profile)
	// 	}

	// 	for _, pk := range profileKeys {
	// 		if pk == registry.ProfileOCT {
	// 			fmt.Println("OCT Profile doesn't support for CycloneDX SBOM")
	// 			os.Exit(0)
	// 		}
	// 	}
	// }

	res, err := SBOMEvaluation(ctx, catalog, cfg, doc)

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
	if profilePresent(cfg) {
		return evaluateProfiles(ctx, catal, cfg, doc)
	}
	return evaluateComprehensive(ctx, catal, cfg, doc)
}

func profilePresent(cfg config.Config) bool {
	return len(cfg.Profile) > 0
}

// evaluateProfiles computes profile-based results for the given SBOM document.
// It resolves profile keys from cfg.Profile, evaluates them via the catalog,
// fills the result (score, grade, and per-profile results), and returns it.
func evaluateProfiles(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	result := api.NewResult(doc)

	// Resolve profiles
	profileKeys := catal.ResolveProfileKeys(cfg.Profile)
	if len(profileKeys) == 0 {
		return *result, fmt.Errorf("no valid profiles resolved from: %v", cfg.Profile)
	}

	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
		for _, pk := range profileKeys {
			if pk == registry.ProfileOCT {
				fmt.Println("OCT Profiles doesn't support for Cyclonedx SBOM")
				os.Exit(0)
			}
		}
	}

	// Evaluate profiles
	profResults := profiles.Evaluate(ctx, catal, profileKeys, doc)

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

	catKeys := selectCategoriesToScore(cfg, catal)
	if len(catKeys) == 0 {
		return api.Result{}, fmt.Errorf("no categories to score (check config filters)")
	}

	comprResult := comprehenssive.Evaluate(ctx, catKeys, catal, doc)
	result.Comprehensive = &comprResult

	log.Debugf("selected categories for evaluation: %s", catKeys)

	result.InterlynkScore = formulae.ComputeInterlynkComprScore(comprResult.CatResult)
	result.Grade = formulae.ToGrade(result.InterlynkScore)

	return *result, nil
}
