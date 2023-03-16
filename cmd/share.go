/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/interlynk-io/sbomqs/pkg/share"
	"github.com/spf13/cobra"
)

// shareCmd represents the share command
var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "share your sbom quality score with others",
	Long: `We need an easy way to communicate with sbom creators/generators
	about the quality of their sboms. sbomqs produces a comprehensive score,
	which can be shared with others. We hope this can be use do drive quality
	improvements in the sbom ecosystem.
	
	Please note, the SBOM never leaves your environment. We only post
	the sbomqs score json to sbombenchmark.dev for sharing purposes only.

	For more information, please visit https://sbombenchmark.dev
	`,
	SilenceUsage: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return fmt.Errorf("share requires a single argument, the path to the sbom file")
		}

		return nil
	},

	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())

		sbomFileName := args[0]
		doc, scores, err := processFile(ctx, sbomFileName, nil)

		if err != nil {
			fmt.Printf("Error processing file %s: %s", sbomFileName, err)
			return err
		}
		url, err := share.Share(ctx, doc, scores, sbomFileName)
		if err != nil {
			fmt.Printf("Error sharing file %s: %s", sbomFileName, err)
			return err
		}
		nr := reporter.NewReport(ctx,
			[]sbom.Document{doc},
			[]scorer.Scores{scores},
			[]string{sbomFileName},
			reporter.WithFormat(strings.ToLower("basic")))
		nr.Report()
		fmt.Printf("ShareLink: %s\n", url)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(shareCmd)
}
