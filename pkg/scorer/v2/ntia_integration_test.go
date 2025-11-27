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

package integration

import (
	"context"
	"math"
	"path/filepath"
	"sort"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/score"
	"github.com/stretchr/testify/require"
)

type expectedNTIAScore struct {
	Score    float64
	Grade    string
	Required int  // Number of required fields compliant (out of 8)
	Optional int  // Number of optional fields present (out of 4)
}

func Test_NTIAProfileForStaticSBOMFiles(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedNTIAScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 8.8, Grade: "B", Required: 7, Optional: 3},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 3.8, Grade: "F", Required: 3, Optional: 2},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 6, Optional: 2},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 4, Optional: 3},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 6, Optional: 3},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 3.8, Grade: "F", Required: 3, Optional: 2},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		
		// CycloneDX test cases  
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 10.0, Grade: "A", Required: 8, Optional: 3},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 2.5, Grade: "F", Required: 2, Optional: 0},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 6, Optional: 1},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 6, Optional: 2},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := "NTIA_" + filename
		
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{
				Profile: []string{string(registry.ProfileNTIA)},
			}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				require.NotNil(t, r.Profiles, "Profile results should not be nil")
				require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")
				
				profResult := r.Profiles.ProfResult[0]
				require.Equal(t, "NTIA Minimum Elements (2021)", profResult.Name)
				
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
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Required: %d/8 | Optional: %d/4", 
					filename, gotRounded, profResult.Grade, requiredCompliant, optionalPresent)
				t.Logf("  Expected: Score: %.1f | Grade: %s | Required: %d/8 | Optional: %d/4",
					want.Score, want.Grade, want.Required, want.Optional)

				// compare NTIA score
				require.InDelta(t, want.Score, gotRounded, 1e-9,
					"NTIA score (rounded to 1 decimal) mismatch for %s", filename)

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

func Test_NTIAProfileForStaticSBOMFiles_Summary(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedNTIAScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Score: 8.8, Grade: "B", Required: 7, Optional: 3},
		filepath.Join(base, "spdx-minimal.json"):          {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "spdx-no-version.json"):       {Score: 3.8, Grade: "F", Required: 3, Optional: 2},
		filepath.Join(base, "spdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 6, Optional: 2},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 4, Optional: 3},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 6, Optional: 3},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "spdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Score: 3.8, Grade: "F", Required: 3, Optional: 2},
		filepath.Join(base, "spdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		
		// CycloneDX test cases  
		filepath.Join(base, "cdx-perfect-score.json"):    {Score: 10.0, Grade: "A", Required: 8, Optional: 3},
		filepath.Join(base, "cdx-minimal.json"):          {Score: 2.5, Grade: "F", Required: 2, Optional: 0},
		filepath.Join(base, "cdx-no-version.json"):       {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "cdx-no-checksums.json"):     {Score: 7.5, Grade: "C", Required: 6, Optional: 1},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Score: 5.0, Grade: "D", Required: 4, Optional: 2},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Score: 7.5, Grade: "C", Required: 6, Optional: 2},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
		filepath.Join(base, "cdx-no-authors.json"):       {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		filepath.Join(base, "cdx-old-version.json"):      {Score: 5.0, Grade: "D", Required: 4, Optional: 1},
	}

	// Sort test cases for organized output
	var paths []string
	for path := range testCases {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	allPassed := true
	failCount := 0

	for _, path := range paths {
		want := testCases[path]
		filename := filepath.Base(path)

		cfg := config.Config{
			Profile: []string{string(registry.ProfileNTIA)},
		}
		pathList := []string{path}

		ctx := context.Background()

		results, err := score.ScoreSBOM(ctx, cfg, pathList)
		require.NoError(t, err)

		for _, r := range results {
			require.NotNil(t, r.Profiles, "Profile results should not be nil")
			require.Len(t, r.Profiles.ProfResult, 1, "Should have exactly one profile result")
			
			profResult := r.Profiles.ProfResult[0]
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

			// Check if test passes
			scoreMatch := math.Abs(want.Score-gotRounded) < 1e-9
			gradeMatch := want.Grade == profResult.Grade
			requiredMatch := want.Required == requiredCompliant
			optionalMatch := want.Optional == optionalPresent
			passed := scoreMatch && gradeMatch && requiredMatch && optionalMatch

			if !passed {
				allPassed = false
				failCount++
				// Only print failures
				t.Errorf("NTIA test failed for %s: Score: got %.1f want %.1f, Grade: got %s want %s",
					filename, gotRounded, want.Score, profResult.Grade, want.Grade)
			}

			// Verify assertions
			require.InDelta(t, want.Score, gotRounded, 1e-9,
				"NTIA score (rounded to 1 decimal) mismatch for %s", filename)
			require.Equal(t, want.Grade, profResult.Grade,
				"Grade mismatch for %s", filename)
			require.Equal(t, want.Required, requiredCompliant,
				"Required fields compliance count mismatch for %s", filename)
			require.Equal(t, want.Optional, optionalPresent,
				"Optional fields present count mismatch for %s", filename)
		}
	}

	// Only print summary
	if allPassed {
		t.Logf("NTIA Profile: ✓ All %d test cases PASSED", len(testCases))
	} else {
		t.Errorf("NTIA Profile: ✗ %d/%d test cases FAILED", failCount, len(testCases))
	}
}

func Test_NTIAProfileDetailedFieldAnalysis(t *testing.T) {
	// Test a single file with detailed field analysis
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")
	testFile := filepath.Join(base, "cdx-perfect-score.json")
	
	cfg := config.Config{
		Profile: []string{string(registry.ProfileNTIA)},
	}
	paths := []string{testFile}
	
	ctx := context.Background()
	results, err := score.ScoreSBOM(ctx, cfg, paths)
	require.NoError(t, err)
	require.Len(t, results, 1)
	
	r := results[0]
	require.NotNil(t, r.Profiles)
	require.Len(t, r.Profiles.ProfResult, 1)
	
	profResult := r.Profiles.ProfResult[0]
	
	// Count summary
	requiredCount, requiredCompliant := 0, 0
	optionalCount, optionalPresent := 0, 0
	
	for _, item := range profResult.Items {
		if item.Required {
			requiredCount++
			if item.Score >= 10.0 {
				requiredCompliant++
			}
		} else {
			optionalCount++
			if item.Score >= 10.0 {
				optionalPresent++
			}
		}
	}
	
	// Verify counts
	require.Equal(t, 8, requiredCount, "Should have 8 required fields")
	require.Equal(t, 4, optionalCount, "Should have 4 optional fields")
	require.Equal(t, 8, requiredCompliant, "CDX perfect score should have all required fields")
	require.Equal(t, 3, optionalPresent, "CDX perfect score should have 3 optional fields")
	
	t.Logf("NTIA Field Analysis: Score: %.1f/10.0, Grade: %s, Required: %d/%d, Optional: %d/%d",
		profResult.InterlynkScore, profResult.Grade, requiredCompliant, requiredCount, optionalPresent, optionalCount)
}

func Test_NTIAProfile_CLIModes(t *testing.T) {
	// Test basic and JSON output modes with NTIA profile
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")
	
	testCases := []struct {
		name     string
		file     string
		expected expectedNTIAScore
	}{
		{
			name:     "CDX Perfect Score",
			file:     "cdx-perfect-score.json",
			expected: expectedNTIAScore{Score: 10.0, Grade: "A", Required: 8, Optional: 3},
		},
		{
			name:     "CDX Minimal",
			file:     "cdx-minimal.json",
			expected: expectedNTIAScore{Score: 2.5, Grade: "F", Required: 2, Optional: 0},
		},
		{
			name:     "SPDX Perfect Score",
			file:     "spdx-perfect-score.json",
			expected: expectedNTIAScore{Score: 8.8, Grade: "B", Required: 7, Optional: 3},
		},
		{
			name:     "SPDX Minimal",
			file:     "spdx-minimal.json",
			expected: expectedNTIAScore{Score: 3.8, Grade: "F", Required: 3, Optional: 1},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFile := filepath.Join(base, tc.file)
			
			cfg := config.Config{
				Profile: []string{string(registry.ProfileNTIA)},
			}
			paths := []string{testFile}
			
			ctx := context.Background()
			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)
			require.Len(t, results, 1)
			
			r := results[0]
			require.NotNil(t, r.Profiles)
			require.Len(t, r.Profiles.ProfResult, 1)
			
			profResult := r.Profiles.ProfResult[0]
			gotRounded := math.Round(profResult.InterlynkScore*10) / 10
			
			require.InDelta(t, tc.expected.Score, gotRounded, 1e-9,
				"Score mismatch for %s", tc.file)
			require.Equal(t, tc.expected.Grade, profResult.Grade,
				"Grade mismatch for %s", tc.file)
		})
	}
}