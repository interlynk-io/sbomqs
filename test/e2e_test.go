package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/stretchr/testify/assert"
)

func TestSbomqsNTIAMissingAuthor(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_author_sbom.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingComponentName(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_component_name.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingDependencies(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_dependency_relationship.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingComponentSupplierName(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_supplier_name.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingTimestamp(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_timestamp.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingComponentUniqueIDs(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_unique_identifiers.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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

func TestSbomqsNTIAForMissingComponentVersion(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		filter           *engine.Params
		expectedAvgScore float64
	}{
		{
			name:  "Check SBOM score for NTIA category and `comp_with_name` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"comp_with_name"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_supplier` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"comp_with_supplier"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_uniq_ids` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"comp_with_uniq_ids"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `comp_with_version` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"comp_with_version"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 0.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_authors` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"sbom_authors"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_creation_timestamp` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"sbom_creation_timestamp"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category and `sbom_dependencies` feature",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Features: []string{"sbom_dependencies"},
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 10.0,
		},
		{
			name:  "Check SBOM score for NTIA category",
			input: "./data/missing_component_version.json",
			filter: &engine.Params{
				Category: "NTIA-minimum-elements",
			},
			expectedAvgScore: 8.6,
		},
	}

	for _, test := range testCases {
		ctx := context.Background()

		f, err := engine.ValidateFile(ctx, test.input)
		assert.NoError(t, err)
		defer f.Close()

		doc, score, err := engine.GetDocsAndScore(ctx, f, test.filter)
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
