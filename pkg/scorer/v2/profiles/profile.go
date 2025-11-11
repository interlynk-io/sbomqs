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

package profiles

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

// Evaluate evaluates the profiles against an SBOM and returns their results.
// Unknown profile keys are skipped
// Returns collected profile results
func Evaluate(ctx context.Context, catal *catalog.Catalog, profileKeys []catalog.ProfileKey, doc sbom.Document) api.ProfilesResult {
	log := logger.FromContext(ctx)
	log.Debugf("Evaluating profiles: %s", profileKeys)

	results := api.NewProfResults()

	// allProfiles := make([]catalog.ProfSpec, 0, len(profileKeys))

	// for _, key := range profileKeys {
	// 	profile, ok := catal.Profiles[key]
	// 	if ok {
	// 		allProfiles = append(allProfiles, profile)
	// 	}
	// }

	for _, profile := range catal.Profiles {
		profResult := evaluateEachProfile(ctx, doc, profile, catal)
		results.ProfResult = append(results.ProfResult, profResult)
	}

	return results
}

// evaluateEachProfile runs evaluation for a profile.
// It executes all feature checks defined in the profile,
// collects their results, aggregates the scores, and
// returns a completed ProfileResult (with metadata included).
func evaluateEachProfile(ctx context.Context, doc sbom.Document, profile catalog.ProfSpec, catal *catalog.Catalog) api.ProfileResult {
	log := logger.FromContext(ctx)
	log.Debugf("evaluating profile: %s", profile.Name)

	var countNonNA int
	var sumScore float64

	proResult := api.NewProfileResult(profile)

	for _, pFeatKey := range profile.Features {
		for _, spec := range catal.ProfFeatures {
			if spec.Key == pFeatKey.Key {
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

				proResult.Items = append(proResult.Items, pFeatResult)

				if !pFeatScore.Ignore {
					sumScore += pFeatScore.Score
					countNonNA++
				}
			}
		}
	}

	if countNonNA > 0 {
		proResult.Score = sumScore / float64(countNonNA)
	}

	return proResult
}
