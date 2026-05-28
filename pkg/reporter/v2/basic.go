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

package v2

import (
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/olekukonko/tablewriter"
)

func (r *Reporter) basicReport() {
	for _, result := range r.Results {
		format := result.Meta.FileFormat
		spec := result.Meta.Spec
		version := result.Meta.SpecVersion

		if spec == string(sbom.SBOMSpecSPDX) {
			version = strings.Replace(version, "SPDX-", "", 1)
		}

		// Check for feature-only scoring mode
		if result.ProfileContext != "" && result.Comprehensive != nil && len(result.Comprehensive.CatResult) > 0 && result.Comprehensive.CatResult[0].Key == "feature_scoring" {
			r.renderFeatureScore(result)
			continue
		}

		// If comprehensive scoring is present, we're in default mode (no specific profile requested)
		// Show only the Interlynk comprehensive score
		if result.Comprehensive != nil {
			fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\t%s\n", result.Comprehensive.InterlynkScore, result.Comprehensive.Grade, "Interlynk", version, format, result.Meta.Filename)
		} else if result.Profiles != nil && len(result.Profiles.ProfResult) > 0 {
			// Profile-only mode: specific profiles were requested, show them
			for _, prof := range result.Profiles.ProfResult {
				fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\t%s\n", prof.InterlynkScore, prof.Grade, prof.Name, version, format, result.Meta.Filename)
			}
		}
	}
}

// renderFeatureScore outputs feature-level scoring results
func (r *Reporter) renderFeatureScore(result api.Result) {
	catResult := result.Comprehensive.CatResult[0]
	numComponents := result.Meta.NumComponents
	fileName := result.Meta.Filename

	// Header with Profile Context
	fmt.Printf("Feature Quality Score: %.1f/10.0     Grade: %s    Components: %d      EngineVersion: %s    File: %s\n",
		result.Comprehensive.InterlynkScore,
		result.Comprehensive.Grade,
		numComponents,
		EngineVersion,
		fileName)

	// Show profile context
	if result.ProfileContext != "" && result.ProfileContext != "interlynk" {
		fmt.Printf("Profile Context: %s\n\n", getProfileDisplayName(result.ProfileContext))
	} else {
		fmt.Println()
	}

	// Feature Breakdown table using tablewriter
	fmt.Println("Feature Breakdown:")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"FEATURE", "SCORE", "GRADE", "DESC"})
	table.SetRowLine(true)
	table.SetAutoWrapText(false)

	for _, feat := range catResult.Features {
		grade := scoreToGrade(feat.Score)
		table.Append([]string{feat.Key, fmt.Sprintf("%.1f/10.0", feat.Score), grade, feat.Desc})
	}
	table.Render()

	// Overall summary for profile context
	if result.ProfileContext != "" && result.ProfileContext != "interlynk" {
		passed := 0
		for _, feat := range catResult.Features {
			if feat.Score >= 5.0 { // PASS threshold
				passed++
			}
		}
		total := len(catResult.Features)
		fmt.Printf("\nOverall: %d/%d %s requirements passed\n", passed, total, getProfileDisplayName(result.ProfileContext))
	}
}

// getProfileDisplayName returns human-readable profile name
func getProfileDisplayName(profile string) string {
	switch profile {
	case "ntia":
		return "NTIA Minimum Elements (2021)"
	case "ntia-2025":
		return "NTIA Minimum Elements (2025)"
	case "bsi-v1.1":
		return "BSI TR-03183-2 v1.1"
	case "bsi-v2.0":
		return "BSI TR-03183-2 v2.0"
	case "bsi", "bsi-v2.1":
		return "BSI TR-03183-2 v2.1"
	case "oct-v1.1":
		return "OpenChain Telco v1.1"
	case "fsct":
		return "Framing 3rd Edition"
	case "interlynk":
		return "Interlynk Comprehensive"
	default:
		return profile
	}
}

// scoreToGrade converts a score to a grade letter
func scoreToGrade(score float64) string {
	switch {
	case score >= 9.0:
		return "A"
	case score >= 8.0:
		return "B"
	case score >= 7.0:
		return "C"
	case score >= 5.0:
		return "D"
	default:
		return "F"
	}
}
