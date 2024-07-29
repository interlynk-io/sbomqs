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

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/spf13/cobra"
)

var scvsCmd = &cobra.Command{
	Use:          "scvs",
	Short:        "sbom component vs",
	SilenceUsage: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) <= 0 {
			if len(inFile) <= 0 && len(inDirPath) <= 0 {
				return fmt.Errorf("provide a path to an sbom file or directory of sbom files")
			}
		}
		return nil
	},
	RunE: processScvs,
}

func processScvs(cmd *cobra.Command, args []string) error {
	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	ctx := logger.WithLogger(context.Background())
	uCmd := toUserCmd(cmd, args)

	if err := validateFlags(uCmd); err != nil {
		return err
	}

	engParams := toEngineParams(uCmd)
	return engine.RunScvs(ctx, engParams)
}

func init() {
	rootCmd.AddCommand(scvsCmd)

	// Debug Control
	scvsCmd.Flags().BoolP("debug", "D", false, "scvs compliance")

	// Output Control
	// scvsCmd.Flags().BoolP("json", "j", false, "results in json")
	scvsCmd.Flags().BoolP("detailed", "d", true, "results in table format, default")
	// scvsCmd.Flags().BoolP("basic", "b", false, "results in single line format")
}
