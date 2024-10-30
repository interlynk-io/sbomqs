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
	Short: "compliance command checks an SBOM for compliance with SBOM standards",
	Long: `Check if your SBOM complies with various SBOM standards like NTIA minimum elements, BSI TR-03183-2, OpenChain Telco.
	Generate a compliance report for an SBOM file.
	`,
	Example: ` sbomqs compliance --bsi|--oct  [--basic|--json] <SBOM file>

  # Check a BSI TR-03183-2 v1.1 compliance against a SBOM in a table output
  sbomqs compliance --bsi samples/sbomqs-spdx-syft.json

  # Check a BSI TR-03183-2 v1.1 compliance against a SBOM in a JSON output
  sbomqs compliance --bsi --json samples/sbomqs-spdx-syft.json

  # Check a OpenChain Telco compliance against a SBOM in a table output
  sbomqs compliance --oct samples/sbomqs-spdx-syft.json

  # Check a OpenChain Telco compliance against a SBOM in a JSON output
  sbomqs compliance --oct --json samples/sbomqs-spdx-syft.json

  # Check a V3 Framing document compliance  against a SBOM in a table output
  sbomqs compliance --fsct <sbom>

  # Check a V3 Framing document compliance  against a SBOM in a JSON output
  sbomqs compliance --fsct -j <sbom>
`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return fmt.Errorf("compliance requires a single argument, the path to an SBOM file")
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
	engParams.JSON, _ = cmd.Flags().GetBool("json")
	engParams.Color, _ = cmd.Flags().GetBool("color")

	engParams.Ntia, _ = cmd.Flags().GetBool("ntia")
	// engParams.Ntia, _ = cmd.Flags().GetBool("ntia")
	engParams.Bsi, _ = cmd.Flags().GetBool("bsi")
	engParams.Oct, _ = cmd.Flags().GetBool("oct")
	engParams.Fsct, _ = cmd.Flags().GetBool("fsct")

	engParams.Debug, _ = cmd.Flags().GetBool("debug")

	engParams.Path = append(engParams.Path, args[0])

	return engParams
}

func init() {
	rootCmd.AddCommand(complianceCmd)

	// Debug control
	complianceCmd.Flags().BoolP("debug", "D", false, "debug logging")

	// Output control
	complianceCmd.Flags().BoolP("json", "j", false, "json format")
	complianceCmd.Flags().BoolP("basic", "b", false, "basic format")
	complianceCmd.Flags().BoolP("detailed", "d", false, "detailed format")
	complianceCmd.Flags().BoolP("json", "j", false, "output in json format")
	complianceCmd.Flags().BoolP("basic", "b", false, "output in basic format")
	complianceCmd.Flags().BoolP("detailed", "d", false, "output in detailed format")
	complianceCmd.Flags().BoolP("color", "l", false, "output in colorful")

	// complianceCmd.Flags().BoolP("pdf", "p", false, "output in pdf format")
	complianceCmd.MarkFlagsMutuallyExclusive("json", "basic", "detailed")

	// Standards control
	complianceCmd.Flags().BoolP("ntia", "n", false, "NTIA minimum elements (July 12, 2021)")
	complianceCmd.Flags().BoolP("bsi", "c", false, "BSI TR-03183-2 (v1.1)")
	complianceCmd.Flags().BoolP("oct", "t", false, "OpenChain Telco SBOM (v1.0)")
	complianceCmd.Flags().BoolP("fsct", "f", false, "Framing Software Component Transparency (v3)")
}
