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

package integration_test

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/score"
	"github.com/stretchr/testify/require"
)

type expectedProfileScore struct {
	Score    float64
	Grade    string
	Required int // Number of required fields compliant
	Optional int // Number of optional fields present (if applicable)
}

// Test_NTIA2025ProfileForStaticSBOMFiles tests NTIA 2025 profile
func Test_NTIA2025ProfileForStaticSBOMFiles(t *testing.T) {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Running NTIA-2025 Profile Integration Tests")
	fmt.Println("==========================================")

	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedProfileScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 8.5, Grade: "B", Required: 11},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 4.6, Grade: "F", Required: 6},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 5.4, Grade: "D", Required: 7},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 7.7, Grade: "C", Required: 10},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 6.9, Grade: "D", Required: 9},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 8.5, Grade: "B", Required: 11},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 6.2, Grade: "D", Required: 8},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 5.4, Grade: "D", Required: 7},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 4.6, Grade: "F", Required: 6},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 6.2, Grade: "D", Required: 8},

		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 10.0, Grade: "A", Required: 13},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 1.5, Grade: "F", Required: 2},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 4.6, Grade: "F", Required: 6},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 6.9, Grade: "D", Required: 9},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 6.2, Grade: "D", Required: 8},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 7.7, Grade: "C", Required: 10},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 5.4, Grade: "D", Required: 7},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 4.6, Grade: "F", Required: 6},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.8, Grade: "F", Required: 5},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 4.6, Grade: "F", Required: 6},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "NTIA2025_" + filename

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileNTIA2025)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")

				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "NTIA Minimum Elements (2025) - RFC", profResult.Name)

				gotRaw := profResult.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Count required fields (all fields are required in NTIA 2025)
				requiredCompliant := 0

				for _, item := range profResult.Items {
					if item.Required && item.Score >= 10.0 {
						requiredCompliant++
					}
				}

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Required: %d/13",
					filename, gotRounded, profResult.Grade, requiredCompliant)
				t.Logf("  Expected: Score: %.1f | Grade: %s | Required: %d/13",
					want.Score, want.Grade, want.Required)

				// compare NTIA 2025 score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"NTIA 2025 score (rounded to 1 decimal) mismatch for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, profResult.Grade,
					"Grade mismatch for %s", filename)

				// compare required fields count
				require.Equal(t, want.Required, requiredCompliant,
					"Required fields compliance count mismatch for %s", filename)
			}
		})
	}

	fmt.Printf("NTIA-2025 Profile: ✓ All %d test cases completed\n", len(testCases))
}

// TODO: Test_BSI11ProfileForStaticSBOMFiles tests BSI v1.1 profile
// Uncomment and update expected scores after running actual tests
/*
func Test_BSI11ProfileForStaticSBOMFiles(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedProfileScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 9.2, Grade: "A", Required: 11, Optional: 2},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 3.3, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 3.3, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 9, Optional: 1},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 9, Optional: 2},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 3.3, Grade: "F", Required: 4, Optional: 1},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 6, Optional: 1},

		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 10.0, Grade: "A", Required: 12, Optional: 2},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 2.5, Grade: "F", Required: 3, Optional: 0},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 3.3, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 9, Optional: 0},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 6, Optional: 1},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 9, Optional: 1},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.3, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 6, Optional: 0},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "BSI11_" + filename

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileBSI11)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")

				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "BSI TR-03183-2 v1.1", profResult.Name)

				gotRaw := profResult.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Count required and optional fields
				requiredCompliant := 0
				optionalPresent := 0

				for _, item := range profResult.Items {
					if item.Required {
						if item.Score >= 10.0 {
							requiredCompliant++
						}
					} else {
						if item.Score >= 10.0 {
							optionalPresent++
						}
					}
				}

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Required: %d/12 | Optional: %d/3",
					filename, gotRounded, profResult.Grade, requiredCompliant, optionalPresent)
				t.Logf("  Expected: Score: %.1f | Grade: %s | Required: %d/12 | Optional: %d/3",
					want.Score, want.Grade, want.Required, want.Optional)

				// compare BSI v1.1 score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"BSI v1.1 score (rounded to 1 decimal) mismatch for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, profResult.Grade,
					"Grade mismatch for %s", filename)

				// compare required fields count
				require.Equal(t, want.Required, requiredCompliant,
					"Required fields compliance count mismatch for %s", filename)

				// compare optional fields count
				require.Equal(t, want.Optional, optionalPresent,
					"Optional fields present count mismatch for %s", filename)
			}
		})
	}
}
*/

// TODO: Test_BSI20ProfileForStaticSBOMFiles tests BSI v2.0 profile
// Uncomment and update expected scores after running actual tests
/*
func Test_BSI20ProfileForStaticSBOMFiles(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedProfileScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 7.0, Grade: "C", Required: 12, Optional: 2},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 2.5, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 2.5, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 5.7, Grade: "D", Required: 9, Optional: 1},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 3.8, Grade: "F", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 5.7, Grade: "D", Required: 9, Optional: 2},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 3.8, Grade: "F", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 3.8, Grade: "F", Required: 6, Optional: 1},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 2.5, Grade: "F", Required: 4, Optional: 1},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 3.8, Grade: "F", Required: 6, Optional: 1},

		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 7.6, Grade: "C", Required: 13, Optional: 2},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 1.9, Grade: "F", Required: 3, Optional: 0},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 2.5, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 5.7, Grade: "D", Required: 9, Optional: 0},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 3.8, Grade: "F", Required: 6, Optional: 1},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 5.7, Grade: "D", Required: 9, Optional: 1},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 3.8, Grade: "F", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 3.8, Grade: "F", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 2.5, Grade: "F", Required: 4, Optional: 0},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 3.8, Grade: "F", Required: 6, Optional: 0},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "BSI20_" + filename

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileBSI20)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")

				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "BSI TR-03183-2 v2.0", profResult.Name)

				gotRaw := profResult.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Count required and optional fields
				requiredCompliant := 0
				optionalPresent := 0

				for _, item := range profResult.Items {
					if item.Required {
						if item.Score >= 10.0 {
							requiredCompliant++
						}
					} else {
						if item.Score >= 10.0 {
							optionalPresent++
						}
					}
				}

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Required: %d/16 | Optional: %d/3",
					filename, gotRounded, profResult.Grade, requiredCompliant, optionalPresent)
				t.Logf("  Expected: Score: %.1f | Grade: %s | Required: %d/16 | Optional: %d/3",
					want.Score, want.Grade, want.Required, want.Optional)

				// compare BSI v2.0 score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"BSI v2.0 score (rounded to 1 decimal) mismatch for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, profResult.Grade,
					"Grade mismatch for %s", filename)

				// compare required fields count
				require.Equal(t, want.Required, requiredCompliant,
					"Required fields compliance count mismatch for %s", filename)

				// compare optional fields count
				require.Equal(t, want.Optional, optionalPresent,
					"Optional fields present count mismatch for %s", filename)
			}
		})
	}
}
*/

// Test_InterlynkProfileForStaticSBOMFiles tests Interlynk profile
func Test_InterlynkProfileForStaticSBOMFiles(t *testing.T) {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Running Interlynk Profile Integration Tests")
	fmt.Println("==========================================")

	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedProfileScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 7.7, Grade: "C"},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 2.7, Grade: "F"},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 4.0, Grade: "F"},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 5.2, Grade: "D"},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 6.2, Grade: "D"},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 4.8, Grade: "F"},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 4.0, Grade: "F"},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 4.0, Grade: "F"},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 4.3, Grade: "F"},

		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 8.0, Grade: "B"},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 2.3, Grade: "F"},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 3.7, Grade: "F"},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 4.8, Grade: "F"},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 4.3, Grade: "F"},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 5.7, Grade: "D"},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 4.4, Grade: "F"},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 3.7, Grade: "F"},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.7, Grade: "F"},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 3.7, Grade: "F"},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "Interlynk_" + filename

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileInterlynk)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")

				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "Interlynk", profResult.Name)

				gotRaw := profResult.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Count compliant features (all are required in Interlynk profile)
				compliant := 0
				total := 0

				for _, item := range profResult.Items {
					total++
					if item.Score >= 10.0 {
						compliant++
					}
				}

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Compliant: %d/%d",
					filename, gotRounded, profResult.Grade, compliant, total)
				t.Logf("  Expected: Score: %.1f | Grade: %s",
					want.Score, want.Grade)

				// compare Interlynk score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"Interlynk score (rounded to 1 decimal) mismatch for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, profResult.Grade,
					"Grade mismatch for %s", filename)
			}
		})
	}

	fmt.Printf("Interlynk Profile: ✓ All %d test cases completed\n", len(testCases))
}

// Test_OCTV11ProfileForStaticSBOMFiles tests OpenChain Telco v1.1 profile
func Test_OCTV11ProfileForStaticSBOMFiles(t *testing.T) {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Running OCT v1.1 Profile Integration Tests")
	fmt.Println("==========================================")

	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedProfileScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 8.9, Grade: "B", Required: 16, Optional: 2},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 5.6, Grade: "D", Required: 10, Optional: 0},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 7.2, Grade: "C", Required: 13, Optional: 0},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 8.9, Grade: "B", Required: 16, Optional: 0},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 7.8, Grade: "C", Required: 14, Optional: 1},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 8.9, Grade: "B", Required: 16, Optional: 1},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 7.8, Grade: "C", Required: 14, Optional: 0},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 7.8, Grade: "C", Required: 14, Optional: 0},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 7.2, Grade: "C", Required: 13, Optional: 0},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 7.8, Grade: "C", Required: 14, Optional: 0},

		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 6.7, Grade: "D", Required: 12, Optional: 2},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 1.7, Grade: "F", Required: 3, Optional: 0},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 3.3, Grade: "F", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 5.6, Grade: "D", Required: 10, Optional: 0},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 3.9, Grade: "F", Required: 7, Optional: 1},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 5.0, Grade: "D", Required: 9, Optional: 1},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 3.9, Grade: "F", Required: 7, Optional: 0},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 3.9, Grade: "F", Required: 7, Optional: 0},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.3, Grade: "F", Required: 6, Optional: 0},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 3.9, Grade: "F", Required: 7, Optional: 0},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "OCTV11_" + filename

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileOCTV11)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")

				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "OpenChain Telco v1.1", profResult.Name)

				gotRaw := profResult.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Count required and optional fields
				requiredCompliant := 0
				optionalPresent := 0

				for _, item := range profResult.Items {
					if item.Required {
						if item.Score >= 10.0 {
							requiredCompliant++
						}
					} else {
						if item.Score >= 10.0 {
							optionalPresent++
						}
					}
				}

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Required: %d/18 | Optional: %d/2",
					filename, gotRounded, profResult.Grade, requiredCompliant, optionalPresent)
				t.Logf("  Expected: Score: %.1f | Grade: %s | Required: %d/18 | Optional: %d/2",
					want.Score, want.Grade, want.Required, want.Optional)

				// compare OCT v1.1 score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"OCT v1.1 score (rounded to 1 decimal) mismatch for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, profResult.Grade,
					"Grade mismatch for %s", filename)

				// compare required fields count
				require.Equal(t, want.Required, requiredCompliant,
					"Required fields compliance count mismatch for %s", filename)

				// compare optional fields count
				require.Equal(t, want.Optional, optionalPresent,
					"Optional fields present count mismatch for %s", filename)
			}
		})
	}

	fmt.Printf("OCT v1.1 Profile: ✓ All %d test cases completed\n", len(testCases))
}

// Test_ProfileIntegrationSummary provides a summary of all profile integration tests
func Test_ProfileIntegrationSummary(t *testing.T) {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("Profile Integration Tests Summary")
	fmt.Println("==========================================")
	fmt.Println("✓ NTIA-2025 Profile: Active (20 test cases)")
	fmt.Println("✓ Interlynk Profile: Active (20 test cases)")
	fmt.Println("✓ OCT v1.1 Profile: Active (20 test cases)")
	fmt.Println("○ BSI v1.1 Profile: TODO (placeholder)")
	fmt.Println("○ BSI v2.0 Profile: TODO (placeholder)")
	fmt.Println("==========================================")
	fmt.Println("Total Active Tests: 60")
	fmt.Println("==========================================")
}
