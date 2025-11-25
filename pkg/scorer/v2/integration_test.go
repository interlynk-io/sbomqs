package integration_test

import (
	"context"
	"math"
	"path/filepath"
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
		filepath.Join(base, "complete-sbom.cdx.json"):          {Interlynk: 8.0, Grade: "B"},
		filepath.Join(base, "dropwizard-core-2.0.31.cdx.json"): {Interlynk: 6.7, Grade: "D"},
		filepath.Join(base, "sbomqs-cdx.json"):                 {Interlynk: 4.5, Grade: "F"},
		filepath.Join(base, "sbomqs-spdx-sbom-tool.json"):      {Interlynk: 5.1, Grade: "D"},
		filepath.Join(base, "complete-sbom.spdx.json"):         {Interlynk: 8.5, Grade: "B"},
		filepath.Join(base, "sbomqs-spdx-syft-tool.json"):      {Interlynk: 6.6, Grade: "D"},
	}

	for path, want := range testCases {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{}
			paths := []string{path}

			ctx := context.Background()

			results, err := score.ScoreSBOM(ctx, cfg, paths)
			require.NoError(t, err)

			for _, r := range results {
				gotRaw := r.Comprehensive.InterlynkScore
				gotRounded := math.Round(gotRaw*10) / 10

				// compare interlynk score
				require.InDelta(t, want.Interlynk, gotRounded, 1e-9,
					"Interlynk score (rounded to 1 decimal) changed for %s", path)

				// compare grade
				require.Equal(t, want.Grade, r.Comprehensive.Grade,
					"Grade changed for %s", path)
			}
		})
	}
}
