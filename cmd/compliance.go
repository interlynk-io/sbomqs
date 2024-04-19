// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
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

var complianceCmd = &cobra.Command{
	Use:   "compliance <sbom file>",
	Short: "compliance command checks the sbom for compliance with sbom standards",
	Long: `Check if you sbom complies with various sbom standards like NTIA minimum elements, CRA TR-03183.
	Generate a compliance report for the sbom file.
	`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return fmt.Errorf("compliance requires a single argument, the path to the sbom file")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")
		if debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		engParams := setupEngineParams(cmd, args)
		return engine.ComplianceRun(ctx, engParams)
	},
}

func setupEngineParams(cmd *cobra.Command, args []string) *engine.Params {
	engParams := &engine.Params{}

	engParams.Basic, _ = cmd.Flags().GetBool("basic")
	engParams.Detailed, _ = cmd.Flags().GetBool("detailed")
	engParams.Json, _ = cmd.Flags().GetBool("json")

	// engParams.Ntia, _ = cmd.Flags().GetBool("ntia")
	engParams.Cra, _ = cmd.Flags().GetBool("cra")

	engParams.Debug, _ = cmd.Flags().GetBool("debug")

	engParams.Path = append(engParams.Path, args[0])

	return engParams
}

func init() {
	rootCmd.AddCommand(complianceCmd)

	//Debug control
	complianceCmd.Flags().BoolP("debug", "D", false, "enable debug logging")

	//Output control
	complianceCmd.Flags().BoolP("json", "j", false, "output in json format")
	complianceCmd.Flags().BoolP("basic", "b", false, "output in basic format")
	complianceCmd.Flags().BoolP("detailed", "d", false, "output in detailed format")
	//complianceCmd.Flags().BoolP("pdf", "p", false, "output in pdf format")
	complianceCmd.MarkFlagsMutuallyExclusive("json", "basic", "detailed")

	//Standards control
	// complianceCmd.Flags().BoolP("ntia", "n", false, "check for NTIA minimum elements compliance")
	complianceCmd.Flags().BoolP("cra", "c", false, "CRA TR-03183 v1.1 compliance")
	// complianceCmd.MarkFlagsMutuallyExclusive("ntia", "cra")
}
