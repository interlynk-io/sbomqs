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

	"github.com/interlynk-io/sbomqs/cmd/options"
	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"

	"github.com/spf13/cobra"
)

func Score() *cobra.Command {
	o := &options.ScoreOptions{}

	cmd := &cobra.Command{
		Use:          "score",
		Short:        "comprehensive quality score for your sbom",
		SilenceUsage: true,
		Args:         cobra.MinimumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			err := processScore(*o, args)
			if err != nil {
				fmt.Println("err:", err)
			}

			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}

func processScore(scoreOption options.ScoreOptions, args []string) error {
	debug := &scoreOption.Debug
	if *debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	ctx := logger.WithLogger(context.Background())

	engParams := toEngineParams(scoreOption, args)

	return engine.Run(ctx, engParams)
}

func toEngineParams(scoreOption options.ScoreOptions, args []string) *engine.Params {
	return &engine.Params{
		Path:       args[0:],
		Category:   scoreOption.Category,
		Features:   scoreOption.Features,
		Json:       scoreOption.Json,
		Basic:      scoreOption.Basic,
		Detailed:   scoreOption.Detailed,
		Recurse:    scoreOption.Recurse,
		Debug:      scoreOption.Debug,
		ConfigPath: scoreOption.ConfigPath,
	}
}

func init() {
	rootCmd.AddCommand(Score())
}
