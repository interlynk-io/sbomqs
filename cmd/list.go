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
	"errors"
	"fmt"
	"strings"

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
	Example: `  sbomqs list --feature <feature> --option  <path-to-sbom-file> 
	
  # List all components with suppliers
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
		validateparsedListCmd(uCmd)
		if err := validateparsedListCmd(uCmd); err != nil {
			logger.FromContext(ctx).Errorf("Invalid command parameters: %v", err)
			return err
		}

		engParams := fromListToEngineParams(uCmd)
		logger.FromContext(ctx).Debugf("Parsed command: %s", cmd.CommandPath())
		logger.FromContext(ctx).Debugf("Parsed user command: %+v", uCmd)
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

func validateparsedListCmd(uCmd *userListCmd) error {
	if len(uCmd.path) == 0 {
		fmt.Println("Error: path is required")
		return errors.New("path is required")
	}

	if len(uCmd.feature) == 0 {
		fmt.Println("Error: feature is required")
		return errors.New("feature is required")
	}

	// we want to cover these cases:
	// 1. --feature=" comp_with_name" ---> this is totally fine as it has only 1 feature
	// 2. --feature=" comp_with_name " ---> this is also fine as it has only 1 feature
	// 3. --feature="comp_with_name comp_with_version" ---> this is not fine as it has 2 features
	// 4. --feature="comp_with_name, comp_with_version" ---> this is also not fine as it has 2 features

	fmt.Println("Feature: ", uCmd.feature)
	feature := strings.TrimSpace(uCmd.feature)
	if feature == "" {
		fmt.Println("Error: feature cannot be empty")
		return errors.New("feature cannot be empty")
	}

	features := strings.Split(feature, ",")

	if len(features) > 1 {
		fmt.Println("Error: only one feature is allowed")
		return errors.New("only one feature is allowed")
	}

	uCmd.feature = feature

	// TODO: validation of feature
	// // Check if the feature is valid
	// validFeatures := []string{"comp_with_supplier", "comp_valid_licenses", "sbom_authors"}
	// featureFound := false
	// for _, validFeature := range validFeatures {
	// 	if strings.TrimSpace(uCmd.feature) == validFeature {
	// 		featureFound = true
	// 		break
	// 	}
	// }
	// if !featureFound {
	// 	fmt.Printf("Error: invalid feature '%s'. Valid features are: %v\n", uCmd.feature, validFeatures)
	// 	return fmt.Errorf("invalid feature '%s'", uCmd.feature)
	// }

	return nil
}
