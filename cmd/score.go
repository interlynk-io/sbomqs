/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/samber/lo"

	"github.com/spf13/cobra"
)

var (
	inFile       string
	inDirPath    string
	category     string
	feature      string
	reportFormat string
)

// scoreCmd represents the score command
var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "provides a comprehensive quality score for your sbom",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())
		var err error
		if len(category) > 0 && !lo.Contains(scorer.Categories, category) {
			return fmt.Errorf(fmt.Sprintf("Category not found %s in %s", category, strings.Join(scorer.Categories, ",")))
		}

		if len(reportFormat) > 0 && !lo.Contains(reporter.ReportFormats, strings.ToLower(reportFormat)) {
			return fmt.Errorf("report format options are basic or detailed")
		}

		var docs []sbom.Document
		var scores []scorer.Scores
		var paths []string

		if len(inFile) > 0 {
			d, s, e := processFile(ctx, inFile)
			if e != nil {
				return fmt.Errorf("error processing file")
			}
			docs = append(docs, d)
			scores = append(scores, s)
			paths = append(paths, inFile)
		} else if len(inDirPath) > 0 {
			docs, scores, paths, err = processDir(ctx, inDirPath)
		}

		nr := reporter.NewReport(ctx,
			docs,
			scores,
			paths,
			reporter.WithFormat(strings.ToLower(reportFormat)))
		nr.Report()

		return err
	},
}

func init() {
	rootCmd.AddCommand(scoreCmd)
	scoreCmd.Flags().StringVar(&inFile, "filepath", "", "sbom file path")
	scoreCmd.Flags().StringVar(&inDirPath, "dirpath", "", "sbom dir path")
	scoreCmd.MarkFlagsMutuallyExclusive("filepath", "dirpath")
	scoreCmd.Flags().StringVar(&category, "category", "", "scoring category")
	scoreCmd.Flags().StringVar(&reportFormat, "reportFormat", "", "reporting format basic/detailed/json")
}

func processFile(ctx context.Context, filePath string) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", filePath)

	if _, err := os.Stat(filePath); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", filePath)
		fmt.Printf("failed to stat %s\n", filePath)
		return nil, nil, err
	}

	f, err := os.Open(filePath)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", filePath)
		fmt.Printf("failed to open %s\n", filePath)
		return nil, nil, err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", filePath)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", filePath, err)
		return nil, nil, err
	}

	sr := scorer.NewScorer(ctx,
		doc,
		scorer.WithCategory(category),
		scorer.WithFeature(feature))

	scores := sr.Score()

	return doc, scores, nil
}

func processDir(ctx context.Context, dirPath string) ([]sbom.Document, []scorer.Scores, []string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("processing dirpath: %s\n", dirPath)
	files, err := os.ReadDir(dirPath)
	if err != nil {
		log.Debugf("os.ReadDir failed for path:%s\n", dirPath)
		log.Debugf("%s\n", err)
		return nil, nil, nil, err
	}

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		path := filepath.Join(dirPath, file.Name())
		doc, scs, err := processFile(ctx, path)
		if err != nil {
			continue
		}
		docs = append(docs, doc)
		scores = append(scores, scs)
		paths = append(paths, path)
	}
	return docs, scores, paths, nil
}
