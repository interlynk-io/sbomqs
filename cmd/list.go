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

	"github.com/interlynk-io/sbomqs/v2/pkg/engine"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
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
	basic    bool
	json     bool
	detailed bool
	color    bool
	show     bool

	// Debug control
	debug bool
}

// listCmd represents the list command for listing components or SBOM properties based on specified features.
// It can show components that have or are missing specific features like suppliers, licenses, etc.
var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List components or SBOM properties based on feature",
	SilenceUsage: true,
	Example: `  sbomqs list --feature <feature> --option <path-to-sbom-file>

  # List all components with suppliers
  sbomqs list --feature comp_with_supplier samples/sbomqs-spdx-syft.json

  # List all components missing suppliers
  sbomqs list --feature comp_with_supplier --missing samples/sbomqs-spdx-syft.json

  # List all components with valid licenses
  sbomqs list --feature comp_valid_licenses samples/sbomqs-spdx-syft.json

  # List all components with invalid licenses
  sbomqs list --feature comp_valid_licenses --missing samples/sbomqs-spdx-syft.json

  Supporter features are listed here: https://github.com/interlynk-io/sbomqs/v2/blob/main/docs/commands/list.md#supported-features
`,

	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			_ = cmd.Help()
			return fmt.Errorf("please provide a path to an SBOM file or directory")
		}
		if len(args) > 1 {
			return fmt.Errorf("only one file path is allowed, got %d: %v", len(args), args)
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

	json, _ := cmd.Flags().GetBool("json")
	uCmd.json = json

	detailed, _ := cmd.Flags().GetBool("detailed")
	uCmd.detailed = detailed

	color, _ := cmd.Flags().GetBool("color")
	uCmd.color = color

	show, _ := cmd.Flags().GetBool("show")
	uCmd.show = show

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
		JSON:     uCmd.json,
		Detailed: uCmd.detailed,
		Color:    uCmd.color,
		Debug:    uCmd.debug,
		Show:     uCmd.show,
	}
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Filter Control
	listCmd.Flags().String("feature", "", "Filter by feature (e.g., 'sbom_authors', 'comp_with_name', 'sbom_creation_timestamp'); if repeated, last value is used")
	err := listCmd.MarkFlagRequired("feature")
	if err != nil {
		log.Fatal(err)
	}
	listCmd.Flags().BoolP("missing", "m", false, "List components or properties missing the specified feature")

	// Output Control
	listCmd.Flags().BoolP("basic", "b", false, "Results in single-line format")
	listCmd.Flags().BoolP("json", "j", false, "Results in JSON")
	listCmd.Flags().BoolP("detailed", "d", true, "Results in table format, default")
	listCmd.Flags().BoolP("color", "l", false, "Output in color")
	listCmd.Flags().BoolP("show", "s", false, "Show values of features, (default: false)")

	// Debug Control
	listCmd.Flags().BoolP("debug", "D", false, "Enable debug logging")

	// Register flag completion for --feature
	err = listCmd.RegisterFlagCompletionFunc("feature", func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var completions []string
		for feature := range isFeaturePresent {
			if strings.HasPrefix(feature, toComplete) {
				completions = append(completions, feature)
			}
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	})
	if err != nil {
		log.Fatalf("Failed to register flag completion for --feature: %v", err)
	}
}

func validateparsedListCmd(uCmd *userListCmd) error {
	// Check path
	if len(uCmd.path) == 0 {
		return errors.New("path is required")
	}

	// Validate feature
	feature := uCmd.feature
	if feature == "" {
		return errors.New("feature is required")
	}

	// Reject comma-separated lists or any commas
	if strings.Contains(feature, ",") {
		if !strings.HasSuffix(strings.TrimSpace(feature), ",") {
			return fmt.Errorf("--feature expects a single value, got comma-separated list: %q", feature)
		}
		return fmt.Errorf("--feature expects a single value, contains comma: %q", feature)
	}

	// Trim spaces
	cleaned := strings.TrimSpace(feature)

	uCmd.feature = cleaned

	// // Validate against supported features
	// if _, ok := isFeaturePresent[cleaned]; !ok {
	// 	var supportedFeatures []string
	// 	for f := range isFeaturePresent {
	// 		supportedFeatures = append(supportedFeatures, f)
	// 	}
	// 	return fmt.Errorf("feature %q is not supported; supported features are: %s", cleaned, strings.Join(supportedFeatures, ", "))
	// }

	return nil
}

var isFeaturePresent = map[string]bool{
	"comp_with_name":                 true,
	"comp_name":                      true,
	"comp_with_version":              true,
	"comp_version":                   true,
	"comp_with_supplier":             true,
	"comp_supplier":                  true,
	"comp_with_uniq_ids":             true,
	"comp_license":                   true,
	"comp_valid_licenses":            true,
	"comp_with_any_vuln_lookup_id":   true,
	"comp_with_deprecated_licenses":  true,
	"comp_with_multi_vuln_lookup_id": true,
	"comp_with_primary_purpose":      true,
	"comp_with_restrictive_licenses": true,

	"comp_with_checksums":        true,
	"comp_hash":                  true,
	"comp_with_sha256":           true,
	"comp_hash_sha256":           true,
	"comp_with_licenses":         true,
	"comp_with_checksums_sha256": true,
	"comp_with_source_code_uri":  true,
	"comp_with_source_code":      true,
	"comp_with_source_code_hash": true,
	"comp_source_hash":           true,
	"comp_with_executable_uri":   true,
	"comp_with_dependencies":     true,
	"comp_dependencies":          true,
	"comp_depth":                 true,

	// "comp_with_executable_hash":      true,

	"comp_with_valid_licenses":     true,
	"comp_with_associated_license": true,
	"comp_associated_license":      true,
	"comp_with_concluded_license":  true,
	"comp_with_declared_license":   true,
	"comp_no_deprecated_licenses":  true,
	"comp_no_restrictive_licenses": true,

	"comp_with_purpose":          true,
	"comp_purpose":               true,
	"comp_with_purl":             true,
	"comp_with_cpe":              true,
	"comp_purl":                  true,
	"comp_cpe":                   true,
	"comp_with_weak_checksums":   true,
	"comp_with_strong_checksums": true,
	"comp_with_copyright":        true,
	"comp_with_local_id":         true,

	"sbom_creation_timestamp":       true,
	"sbom_timestamp":                true,
	"sbom_authors":                  true,
	"sbom_creator":                  true,
	"sbom_with_creator_and_version": true,
	"sbom_tool":                     true,
	"sbom_with_primary_component":   true,
	"sbom_primary_component":        true,
	"sbom_dependencies":             true,
	"sbom_depth":                    true,
	"sbom_sharable":                 true,
	"sbom_parsable":                 true,
	"sbom_spec":                     true,
	"sbom_spec_declared":            true,
	"sbom_spec_file_format":         true,
	"sbom_file_format":              true,
	"sbom_spec_version":             true,
	"spec_with_version_compliant":   true,
	"sbom_with_uri":                 true,
	"sbom_uri":                      true,
	"sbom_with_vuln":                true,
	"sbom_build_process":            true,
	"sbom_build":                    true,
	"sbom_with_bomlinks":            true,
	"sbom_bomlinks":                 true,
	"sbom_vulnerabilities":          true,
	"sbom_machine_format":           true,
	"sbom_spdxid":                   true,
	"sbom_name":                     true,
	"sbom_organization":             true,
	"sbom_schema_valid":             true,
	// "sbom_with_signature":           true,
}
