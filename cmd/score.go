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

		if len(inFile) > 0 {
			err = processFile(ctx, inFile, false)
		} else if len(inDirPath) > 0 {
			err = processDir(ctx, inDirPath)
		}

		return err
	},
}

func init() {
	rootCmd.AddCommand(scoreCmd)
	scoreCmd.Flags().StringVarP(&inFile, "filepath", "f", "", "sbom file path")
	scoreCmd.Flags().StringVarP(&inDirPath, "dirpath", "d", "", "sbom dir path")
	scoreCmd.MarkFlagsMutuallyExclusive("filepath", "dirpath")
	scoreCmd.Flags().StringVarP(&category, "category", "c", "", "scoring category")
	scoreCmd.Flags().StringVarP(&reportFormat, "reportFormat", "r", "", "reporting format basic or detailed")
}

func processFile(ctx context.Context, filePath string, basic bool) error {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", filePath)

	if _, err := os.Stat(filePath); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", filePath)
		fmt.Printf("failed to stat %s\n", filePath)
		return err
	}

	f, err := os.Open(filePath)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", filePath)
		fmt.Printf("failed to open %s\n", filePath)
		return err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", filePath)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s\n", filePath)
		return err
	}

	if len(category) > 0 && !lo.Contains(scorer.Categories, category) {
		return fmt.Errorf(fmt.Sprintf("Category not found %s in %s", category, strings.Join(scorer.Categories, ",")))
	}

	if len(reportFormat) > 0 && !lo.Contains(reporter.ReportFormats, reportFormat) {
		return fmt.Errorf("report format options are basic or detailed")
	}

	sr := scorer.NewScorer(ctx,
		doc,
		scorer.WithCategory(category),
		scorer.WithFeature(feature))

	scores := sr.Score()

	nr := reporter.NewReport(ctx,
		doc,
		scores,
		reporter.WithFormat(strings.ToLower(reportFormat)),
		reporter.WithFilePath(filePath))
	nr.Report()

	return nil
}

func processDir(ctx context.Context, dirPath string) error {
	log := logger.FromContext(ctx)
	log.Debugf("processing dirpath: %s\n", dirPath)
	files, err := os.ReadDir(dirPath)
	if err != nil {
		log.Debugf("os.ReadDir failed for path:%s\n", dirPath)
		log.Debugf("%s\n", err)
		return err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		processFile(ctx, filepath.Join(dirPath, file.Name()), true)
	}
	return nil
}
