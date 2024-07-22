package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/stretchr/testify/assert"
)

func TestSBOMQSMissingAuthorScore(t *testing.T) {
	testCases := []struct {
		input            string
		feature          *engine.Params
		expectedAvgScore float64
	}{
		{
			input: "./data/missing_author_sbom.json",
			feature: &engine.Params{
				Features: []string{"sbom_authors"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/missing_component_name.json",
			feature: &engine.Params{
				Features: []string{"comp_with_name"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/missing_dependency_relationship.json",
			feature: &engine.Params{
				Features: []string{"sbom_dependencies"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/missing_supplier_name.json",
			feature: &engine.Params{
				Features: []string{"comp_with_supplier"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/missing_timestamp.json",
			feature: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/missing_unique_identifiers.json",
			feature: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
			},
			expectedAvgScore: 0.0,
		},
		{
			input: "./data/no_element_missing.json",
			feature: &engine.Params{
				Features: []string{""},
			},
			expectedAvgScore: 8.7,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.feature)
		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, score)

		// expectedAvgScore := 0.0
		expectedAvgScore := score.AvgScore()
		if expectedAvgScore != 0.0 {
			actualAvgScore := fmt.Sprintf("%0.1f", score.AvgScore())
			fmt.Println("actualAvgScore: ", actualAvgScore)
			assert.Equal(t, fmt.Sprintf("%0.1f", test.expectedAvgScore), actualAvgScore)
		} else {
			assert.Equal(t, test.expectedAvgScore, score.AvgScore())
		}
	}
}
