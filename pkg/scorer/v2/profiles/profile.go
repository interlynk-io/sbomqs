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

// Package profiles evaluates SBOMs scoring against compliance profiles such as NTIA,
// BSI, OCT and others. It runs each profile’s feature checks, decides which
// requirements passed, computes Interlynk profile scores and grades, and
// returns a structured result that higher-level code or the CLI can display
package profiles

import (
	"context"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"go.uber.org/zap"
)

// Evaluate evaluates the profiles against an SBOM and returns their results.
// Unknown profile keys are skipped
// Returns collected profile results
func Evaluate(ctx context.Context, catal *catalog.Catalog, doc sbom.Document) api.ProfilesResult {
	log := logger.FromContext(ctx)
	log.Info("Starting profile evaluation",
		zap.Int("profiles", len(catal.Profiles)),
	)

	results := api.NewProfResults()

	for _, profile := range catal.Profiles {
		if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) && profile.Key == "oct" {
			log.Warn("Skipping profile evaluation due to unsupported SBOM spec",
				zap.String("profile", profile.Name),
				zap.String("spec", doc.Spec().GetSpecType()),
			)
			continue
		}

		profResult := evaluateEachProfile(ctx, doc, profile)
		results.ProfResult = append(results.ProfResult, profResult)
	}

	log.Info("Profile evaluation completed",
		zap.Int("evaluated", len(results.ProfResult)),
	)
	return results
}

// evaluateEachProfile runs evaluation for a profile.
// It executes all feature checks defined in the profile,
// collects their results, aggregates the scores, and
// returns a completed ProfileResult (with metadata included).
func evaluateEachProfile(ctx context.Context, doc sbom.Document, profile catalog.ProfSpec) api.ProfileResult {
	log := logger.FromContext(ctx)
	log.Debug("Evaluating profile",
		zap.String("profile", profile.Name),
		zap.Int("features", len(profile.Features)),
	)

	// if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) && profile.Key == "oct" {
	// 	log.Debugf("Skipping evaluation of oct profile, as it doesn't support for cyclonedx")
	// 	return api.ProfileResult{}
	// }

	var countNonNA int
	var sumScore float64

	proResult := api.NewProfileResult(profile)

	for _, spec := range profile.Features {
		pFeatResult := api.NewProfFeatResult(spec)

		// evaluate feature
		pFeatScore := spec.Evaluate(doc)

		if pFeatScore.Ignore {
			pFeatResult.Passed = !spec.Required
		} else if spec.Required {
			pFeatResult.Passed = (pFeatScore.Score >= 10.0)
		} else {
			pFeatResult.Passed = (pFeatScore.Score > 0.0)
		}

		pFeatResult.Score = pFeatScore.Score
		pFeatResult.Desc = pFeatScore.Desc

		// proResult.Score += pFeatResult.Score
		proResult.Items = append(proResult.Items, pFeatResult)

		// Only count required fields for scoring
		if !pFeatScore.Ignore && spec.Required {
			sumScore += pFeatScore.Score
			countNonNA++
		}

	}
	proResult.InterlynkScore = formulae.ComputeInterlynkProfScore(proResult)
	proResult.Grade = formulae.ToGrade(proResult.InterlynkScore)
	if countNonNA > 0 {
		proResult.Score = sumScore / float64(countNonNA)
	}

	log.Debug("Evaluating profile",
		zap.String("profile", profile.Name),
		zap.Int("features", len(profile.Features)),
	)
	return proResult
}
