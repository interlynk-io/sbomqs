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
	"log"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/spf13/cobra"
)

// dtrackScoreCmd represents the dtrackScore command
var dtrackScoreCmd = &cobra.Command{
	Use:          "dtrackScore <project-id>",
	Short:        "generate an sbom quality score for a given project id from dependency track",
	Long:         `dtrackScore allows your to score the sbom quality of a project from dependency track.`,
	SilenceUsage: true,
	Args:         cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}
		ctx := logger.WithLogger(context.Background())

		dtParams, err := extractArgs(cmd, args)
		if err != nil {
			log.Fatalf("failed to extract args: %v", err)
		}

		return engine.DtrackScore(ctx, dtParams)
	},
}

func extractArgs(cmd *cobra.Command, args []string) (*engine.DtParams, error) {
	params := &engine.DtParams{}

	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return nil, err
	}

	apiKey, err := cmd.Flags().GetString("api-key")
	if err != nil {
		return nil, err
	}

	json, _ := cmd.Flags().GetBool("json")
	basic, _ := cmd.Flags().GetBool("basic")
	detailed, _ := cmd.Flags().GetBool("detailed")

	params.Url = url
	params.ApiKey = apiKey

	params.Json = json
	params.Basic = basic
	params.Detailed = detailed

	params.TagProjectWithScore, _ = cmd.Flags().GetBool("tag-project-with-score")

	for _, arg := range args {
		argID, err := uuid.Parse(arg)
		if err != nil {
			return nil, err
		}
		params.ProjectIds = append(params.ProjectIds, argID)
	}

	return params, nil
}

func init() {
	rootCmd.AddCommand(dtrackScoreCmd)
	dtrackScoreCmd.Flags().StringP("url", "u", "", "dependency track url https://localhost:8080/")
	dtrackScoreCmd.Flags().StringP("api-key", "k", "", "dependency track api key, requires VIEW_PORTFOLIO for scoring and PORTFOLIO_MANAGEMENT for tagging")
	dtrackScoreCmd.MarkFlagRequired("url")
	dtrackScoreCmd.MarkFlagRequired("api-key")

	dtrackScoreCmd.Flags().BoolP("debug", "D", false, "enable debug logging")

	dtrackScoreCmd.Flags().BoolP("json", "j", false, "results in json")
	dtrackScoreCmd.Flags().BoolP("detailed", "d", false, "results in table format, default")
	dtrackScoreCmd.Flags().BoolP("basic", "b", false, "results in single line format")

	dtrackScoreCmd.Flags().BoolP("tag-project-with-score", "t", false, "tag project with sbomqs score")
}
