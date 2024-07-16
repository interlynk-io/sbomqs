package test

import (
	"context"
	"os"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
)

func TestSBOMQSMissingAuthorScore(t *testing.T) {
	// Define the input file and expected score
	inputFile := "./data/missing_author_sbom.json"
	expectedScore := 0.0

	ctx := context.Background()
	log := logger.FromContext(ctx)

	f, err := os.Open(inputFile)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	path := inputFile
	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", path)
		log.Debugf("%s\n", err)
		t.Fatalf("Failed to parse %s: %s\n", inputFile, err)

	}

	sr := scorer.NewScorer(ctx, doc)
	var ep engine.Params

	ep.Features = []string{"sbom_authors"}

	if len(ep.Features) > 0 {
		for _, feature := range ep.Features {
			if len(feature) <= 0 {
				continue
			}
			sr.AddFilter(feature, scorer.Feature)
		}
	}

	scores := sr.Score()

	// Check if the score matches the expected value
	if scores.AvgScore() != expectedScore {
		t.Errorf("Expected score %v, got %v", expectedScore, scores.AvgScore())
	}
}
