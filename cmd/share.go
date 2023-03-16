// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
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
	Use:   "share <sbom file>",
	Short: "share your sbom quality score with others",
	Long: `share command creates a permanent link to the score result from an easy-to-understand web page.

Due to privacy considerations, the SBOM never leaves your environment, and only
the score report (includes filename) is sent to https://sbombenchmark.dev (exact JSON form is used).

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
