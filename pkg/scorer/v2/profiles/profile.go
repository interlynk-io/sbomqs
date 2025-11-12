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
	"fmt"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

// Evaluate evaluates the profiles against an SBOM and returns their results.
// Unknown profile keys are skipped
// Returns collected profile results
func Evaluate(ctx context.Context, catal *catalog.Catalog, doc sbom.Document) api.ProfilesResult {
	log := logger.FromContext(ctx)
	log.Debugf("Intializing Profiles Evaluation ")

	results := api.NewProfResults()

	for _, profile := range catal.Profiles {
		profResult := evaluateEachProfile(ctx, doc, profile)
		results.ProfResult = append(results.ProfResult, profResult)
	}

	return results
}

// evaluateEachProfile runs evaluation for a profile.
// It executes all feature checks defined in the profile,
// collects their results, aggregates the scores, and
// returns a completed ProfileResult (with metadata included).
func evaluateEachProfile(ctx context.Context, doc sbom.Document, profile catalog.ProfSpec) api.ProfileResult {
	log := logger.FromContext(ctx)
	log.Debugf("evaluating profile one by one, processing profile: %s", profile.Name)

	var countNonNA int
	var sumScore float64

	proResult := api.NewProfileResult(profile)

	for _, spec := range profile.Features {
		pFeatResult := api.NewProfFeatResult(spec)

		// evaluate feature
		pFeatScore := spec.Evaluate(doc)
		fmt.Println("pFeatScore.Score: ", pFeatScore.Score)

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

	if countNonNA > 0 {
		proResult.Score = sumScore / float64(countNonNA)
	}

	return proResult
}
