// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

// userListCmd holds the configuration for the list command
type userListCmd struct {
	// Input control
	path string

	// Filter control
	feature string
	missing bool

	// Output control
	basic bool

	// Debug control
	debug bool
}

// listCmd lists components or SBOM properties based on specified features
var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List components or SBOM properties based on features",
	SilenceUsage: true,
	Example: `  # List all components with suppliers
  sbomqs list --feature comp_with_supplier samples/sbomqs-spdx-syft.json

  # List all components missing suppliers
  sbomqs list --feature comp_with_supplier --missing samples/sbomqs-spdx-syft.json

  # List all components with valid licenses
  sbomqs list --feature comp_valid_licenses samples/sbomqs-spdx-syft.json

  # List all components with invalid licenses
  sbomqs list --feature comp_valid_licenses --missing samples/sbomqs-spdx-syft.json
`,

	Args: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("requires a path to an SBOM file or directory of SBOM files")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger based on debug flag
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())
		uCmd := parseListParams(cmd, args)

		engParams := fromListToEngineParams(uCmd)
		return engine.ListRun(ctx, engParams)
	},
}

func parseListParams(cmd *cobra.Command, args []string) *userListCmd {
	uCmd := &userListCmd{}

	// Input control
	uCmd.path = args[0]

	// Filter control
	feature, _ := cmd.Flags().GetString("feature")
	uCmd.feature = feature
	missing, _ := cmd.Flags().GetBool("missing")
	uCmd.missing = missing

	// Output control
	basic, _ := cmd.Flags().GetBool("basic")
	uCmd.basic = basic

	// Debug control
	debug, _ := cmd.Flags().GetBool("debug")
	uCmd.debug = debug

	return uCmd
}

func fromListToEngineParams(uCmd *userListCmd) *engine.Params {
	return &engine.Params{
		Path:     []string{uCmd.path},
		Features: []string{uCmd.feature},
		Missing:  uCmd.missing,
		Basic:    uCmd.basic,
		Debug:    uCmd.debug,
	}
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Filter Control
	listCmd.Flags().StringP("feature", "f", "", "filter by feature (e.g., 'comp_with_supplier', 'sbom_authors')")
	listCmd.MarkFlagRequired("feature")
	listCmd.Flags().BoolP("missing", "m", false, "list components or properties missing the specified feature")

	// Output Control
	listCmd.Flags().BoolP("basic", "b", true, "results in single-line format")

	// Debug Control
	listCmd.Flags().BoolP("debug", "D", false, "enable debug logging")
}
