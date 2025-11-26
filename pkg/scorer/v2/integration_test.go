package integration_test

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/score"
	"github.com/stretchr/testify/require"
)

type expectedScore struct {
	Interlynk float64
	Grade     string
}

func Test_ScoreForStaticSBOMFiles(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Interlynk: 9.4, Grade: "A"},
		filepath.Join(base, "spdx-minimal.json"):          {Interlynk: 2.8, Grade: "F"},
		filepath.Join(base, "spdx-no-version.json"):       {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-no-checksums.json"):     {Interlynk: 6.1, Grade: "D"},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Interlynk: 5.1, Grade: "D"},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Interlynk: 7.8, Grade: "C"},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Interlynk: 4.5, Grade: "F"},
		filepath.Join(base, "spdx-no-authors.json"):       {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-old-version.json"):      {Interlynk: 5.1, Grade: "D"},
		
		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Interlynk: 9.1, Grade: "A"},
		filepath.Join(base, "cdx-minimal.json"):          {Interlynk: 1.9, Grade: "F"},
		filepath.Join(base, "cdx-no-version.json"):       {Interlynk: 4.2, Grade: "F"},
		filepath.Join(base, "cdx-no-checksums.json"):     {Interlynk: 5.5, Grade: "D"},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Interlynk: 4.6, Grade: "F"},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Interlynk: 7.1, Grade: "C"},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Interlynk: 4.0, Grade: "F"},
		filepath.Join(base, "cdx-no-authors.json"):       {Interlynk: 4.3, Grade: "F"},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Interlynk: 4.3, Grade: "F"},
		filepath.Join(base, "cdx-old-version.json"):      {Interlynk: 4.3, Grade: "F"},
	}

	for path, want := range testCases {
		filename := filepath.Base(path)
		testName := filename
		
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				gotRaw := r.Comprehensive.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// Log the score for visibility
				t.Logf("File: %s | Score: %.1f/10.0 | Grade: %s | Expected: %.1f (%s)", 
					filename, gotRounded, r.Comprehensive.Grade, want.Interlynk, want.Grade)

				// compare interlynk score
				require.InDelta(t, want.Interlynk, gotRounded, 1e-9,
					"Interlynk score (rounded to 1 decimal) changed for %s", filename)

				// compare grade
				require.Equal(t, want.Grade, r.Comprehensive.Grade,
					"Grade changed for %s", filename)
			}
		})
	}
}

func Test_ScoreForStaticSBOMFiles_Summary(t *testing.T) {
	base := filepath.Join("..", "..", "..", "testdata", "fixtures")

	testCases := map[string]expectedScore{
		// SPDX test cases
		filepath.Join(base, "spdx-perfect-score.json"):    {Interlynk: 9.4, Grade: "A"},
		filepath.Join(base, "spdx-minimal.json"):          {Interlynk: 2.8, Grade: "F"},
		filepath.Join(base, "spdx-no-version.json"):       {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-no-checksums.json"):     {Interlynk: 6.1, Grade: "D"},
		filepath.Join(base, "spdx-weak-checksums.json"):   {Interlynk: 5.1, Grade: "D"},
		filepath.Join(base, "spdx-no-dependencies.json"):  {Interlynk: 7.8, Grade: "C"},
		filepath.Join(base, "spdx-invalid-licenses.json"): {Interlynk: 4.5, Grade: "F"},
		filepath.Join(base, "spdx-no-authors.json"):       {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-no-timestamp.json"):     {Interlynk: 4.7, Grade: "F"},
		filepath.Join(base, "spdx-old-version.json"):      {Interlynk: 5.1, Grade: "D"},
		
		// CycloneDX test cases
		filepath.Join(base, "cdx-perfect-score.json"):    {Interlynk: 9.1, Grade: "A"},
		filepath.Join(base, "cdx-minimal.json"):          {Interlynk: 1.9, Grade: "F"},
		filepath.Join(base, "cdx-no-version.json"):       {Interlynk: 4.2, Grade: "F"},
		filepath.Join(base, "cdx-no-checksums.json"):     {Interlynk: 5.5, Grade: "D"},
		filepath.Join(base, "cdx-weak-checksums.json"):   {Interlynk: 4.6, Grade: "F"},
		filepath.Join(base, "cdx-no-dependencies.json"):  {Interlynk: 7.1, Grade: "C"},
		filepath.Join(base, "cdx-invalid-licenses.json"): {Interlynk: 4.0, Grade: "F"},
		filepath.Join(base, "cdx-no-authors.json"):       {Interlynk: 4.3, Grade: "F"},
		filepath.Join(base, "cdx-no-timestamp.json"):     {Interlynk: 4.3, Grade: "F"},
		filepath.Join(base, "cdx-old-version.json"):      {Interlynk: 4.3, Grade: "F"},
	}

	// Sort test cases for organized output
	var paths []string
	for path := range testCases {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	// Print summary header
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("SBOM SCORING INTEGRATION TEST SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n%-35s %-10s %-10s %-10s %-10s\n", "FILE", "SCORE", "GRADE", "EXPECTED", "STATUS")
	fmt.Println(strings.Repeat("-", 80))

	allPassed := true

	for _, path := range paths {
		want := testCases[path]
		filename := filepath.Base(path)

		cfg := config.Config{}
		pathList := []string{path}

		ctx := context.Background()

		results, err := score.ScoreSBOM(ctx, cfg, pathList)
		require.NoError(t, err)

		for _, r := range results {
			gotRaw := r.Comprehensive.InterlynkScore
			gotRounded := math.Round(gotRaw*10) / 10

			// Check if test passes
			scoreMatch := math.Abs(want.Interlynk-gotRounded) < 1e-9
			gradeMatch := want.Grade == r.Comprehensive.Grade
			passed := scoreMatch && gradeMatch

			status := "✓ PASS"
			if !passed {
				status = "✗ FAIL"
				allPassed = false
			}

			// Format filename for better readability
			displayName := filename
			if len(displayName) > 35 {
				displayName = displayName[:32] + "..."
			}

			// Print result row
			fmt.Printf("%-35s %5.1f/10.0  %-10s %.1f (%s)    %s\n",
				displayName,
				gotRounded,
				r.Comprehensive.Grade,
				want.Interlynk,
				want.Grade,
				status,
			)

			// Verify using testify
			require.InDelta(t, want.Interlynk, gotRounded, 1e-9,
				"Interlynk score changed for %s", filename)
			require.Equal(t, want.Grade, r.Comprehensive.Grade,
				"Grade changed for %s", filename)
		}
	}

	// Print summary footer
	fmt.Println(strings.Repeat("-", 80))
	
	// Group by format
	spdxCount := 0
	cdxCount := 0
	for _, path := range paths {
		if strings.Contains(path, "spdx") {
			spdxCount++
		} else if strings.Contains(path, "cdx") {
			cdxCount++
		}
	}

	fmt.Printf("\nTotal Tests: %d (SPDX: %d, CycloneDX: %d)\n", len(paths), spdxCount, cdxCount)
	
	if allPassed {
		fmt.Println("Status: ✓ All tests passed")
	} else {
		fmt.Println("Status: ✗ Some tests failed")
	}
	
	fmt.Println(strings.Repeat("=", 80))
}
