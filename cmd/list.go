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
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/spf13/cobra"
)

// userListCmd holds the configuration for the list command
type userListCmd struct {
	// Input control
	path []string

	// Filter control
	features []string
	missing  bool

	// Output control
	basic    bool
	json     bool
	detailed bool
	color    bool

	// Debug control
	debug bool
}

// listCmd lists components or SBOM properties based on specified features
var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List components or SBOM properties based on features",
	SilenceUsage: true,
	Example: `  sbomqs list --features <features> --option  <path-to-sbom-file> 
	
  # List all components with suppliers
  sbomqs list --features comp_with_supplier samples/sbomqs-spdx-syft.json

  # List all components missing suppliers
  sbomqs list --features comp_with_supplier --missing samples/sbomqs-spdx-syft.json

  # List all components with valid licenses
  sbomqs list --features comp_valid_licenses samples/sbomqs-spdx-syft.json

  # List all components with invalid licenses
  sbomqs list --features comp_valid_licenses --missing samples/sbomqs-spdx-syft.json

  # List all components of SBOM with comp_with_licenses as well as comp_with_version
  sbomqs list --features="comp_with_licenses,comp_with_version"  samples/photon.spdx.json

  # List all components for both SBOM with comp_with_licenses as well as comp_with_version
  sbomqs list --features="comp_with_licenses,comp_with_version"  samples/photon.spdx.json samples/sbomqs-cdx-cgomod.json

  # component features: 
  [comp_with_name, comp_with_version, comp_with_supplier, comp_with_uniq_ids, comp_valid_licenses, comp_with_any_vuln_lookup_id, 
  comp_with_deprecated_licenses, comp_with_multi_vuln_lookup_id, comp_with_primary_purpose, comp_with_restrictive_licenses, 
  comp_with_checksums, comp_with_licenses]
  
  # sbom features:
  [sbom_creation_timestamp, sbom_authors, sbom_with_creator_and_version, sbom_with_primary_component, sbom_dependencies, 
  sbom_sharable, sbom_parsable, sbom_spec, sbom_spec_file_format, sbom_spec_version ]
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
	uCmd.path = args

	// Filter control
	feature, _ := cmd.Flags().GetString("features")
	features := strings.Split(feature, ",")
	uCmd.features = features

	missing, _ := cmd.Flags().GetBool("missing")
	uCmd.missing = missing

	// Output control
	basic, _ := cmd.Flags().GetBool("basic")
	uCmd.basic = basic

	json, _ := cmd.Flags().GetBool("json")
	uCmd.json = json

	detailed, _ := cmd.Flags().GetBool("detailed")

	uCmd.detailed = detailed

	color, _ := cmd.Flags().GetBool("color")
	uCmd.color = color

	// Debug control
	debug, _ := cmd.Flags().GetBool("debug")
	uCmd.debug = debug

	return uCmd
}

func fromListToEngineParams(uCmd *userListCmd) *engine.Params {
	return &engine.Params{
		Path:     uCmd.path,
		Features: uCmd.features,
		Missing:  uCmd.missing,
		Basic:    uCmd.basic,
		JSON:     uCmd.json,
		Detailed: uCmd.detailed,
		Color:    uCmd.color,
		Debug:    uCmd.debug,
	}
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Filter Control
	listCmd.Flags().StringP("features", "f", "", "filter by feature (e.g. 'sbom_authors',  'comp_with_name', 'sbom_creation_timestamp') ")
	err := listCmd.MarkFlagRequired("features")
	if err != nil {
		log.Fatal(err)
	}
	listCmd.Flags().BoolP("missing", "m", false, "list components or properties missing the specified feature")

	// Output Control
	listCmd.Flags().BoolP("basic", "b", false, "results in single-line format")
	listCmd.Flags().BoolP("json", "j", false, "results in json")
	listCmd.Flags().BoolP("detailed", "d", true, "results in table format, default")
	listCmd.Flags().BoolP("color", "l", false, "output in colorful")

	// Debug Control
	listCmd.Flags().BoolP("debug", "D", false, "enable debug logging")
}

func validateparsedListCmd(uCmd *userListCmd) error {
	if len(uCmd.path) <= 0 {
		fmt.Println("Error: path is required")
		return errors.New("path is required")
	}

	if len(uCmd.features) == 0 {
		fmt.Println("Error: feature is required")
		log.Fatal("at least one feature must be specified")

	}
	// we want to cover these cases:
	// 1. --feature=" comp_with_name" ---> this is totally fine as it has only 1 feature
	// 2. --feature=" comp_with_name " ---> this is also fine as it has only 1 feature
	// 3. --feature="comp_with_name comp_with_version" ---> this is not fine as it has 2 features
	// 4. --feature="comp_with_name, comp_with_version" ---> this is also not fine as it has 2 features

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
