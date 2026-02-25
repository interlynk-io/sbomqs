// Copyright 2026 Interlynk.io
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
	"sort"
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
		debug, _ := cmd.Flags().GetBool("debug")

		// Initialize logger once
		logger.Init(debug)
		defer logger.Sync()

		ctx := logger.WithLogger(context.Background())

		log := logger.FromContext(ctx)
		log.Info("Listing started")

		uCmd := parseListParams(cmd, args)
		if err := validateparsedListCmd(uCmd); err != nil {
			return err
		}

		engParams := fromListToEngineParams(uCmd)
		return engine.ListRun(ctx, engParams)
	},
}

func parseListParams(cmd *cobra.Command, args []string) *userListCmd {
	uCmd := &userListCmd{}

	// -- Input control --
	uCmd.path = args[0]

	// Filter control
	feature, _ := cmd.Flags().GetString("feature")
	uCmd.feature = feature

	missing, _ := cmd.Flags().GetBool("missing")
	uCmd.missing = missing

	// -- Output control --
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

	// -- Debug control --
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

	// -- Filter Control --
	listCmd.Flags().String("feature", "", "Filter by a supported feature (run 'sbomqs features' to list all)")
	_ = listCmd.MarkFlagRequired("feature")

	listCmd.Flags().BoolP("missing", "m", false, "List components or properties missing the specified feature")

	// -- Output Control --
	listCmd.Flags().BoolP("basic", "b", false, "Results in single-line format")
	listCmd.Flags().BoolP("json", "j", false, "Results in JSON")
	listCmd.Flags().BoolP("detailed", "d", true, "Results in table format, default")
	listCmd.Flags().BoolP("color", "l", false, "Output in color")
	listCmd.Flags().BoolP("show", "s", false, "Show values of features, (default: false)")

	// -- Debug Control --
	listCmd.Flags().BoolP("debug", "D", false, "Enable debug logging")

	// Register flag completion for --feature
	err := listCmd.RegisterFlagCompletionFunc("feature",
		func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {

			var completions []string

			for _, f := range FeatureRegistry {
				if strings.HasPrefix(f.Name, toComplete) {
					completions = append(completions, f.Name)
				}
			}

			sort.Strings(completions)

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
	if strings.TrimSpace(feature) == "" {
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

	if _, ok := featureLookup[cleaned]; !ok {
		return fmt.Errorf(
			"feature %q is not supported.\n\nRun \"sbomqs features\" to see supported features.",
			cleaned,
		)
	}

	return nil
}

type Feature struct {
	Name        string
	Category    string
	Description string
}

var FeatureRegistry = []Feature{

	// == SBOM: Metadata & Structure ==

	{Name: "sbom_name", Category: "SBOM", Description: "Validate SBOM name field"},
	{Name: "sbom_creator", Category: "SBOM", Description: "Validate SBOM creator information"},
	{Name: "sbom_authors", Category: "SBOM", Description: "Validate SBOM authors field"},
	{Name: "sbom_creation_timestamp", Category: "SBOM", Description: "Validate SBOM creation timestamp"},
	{Name: "sbom_timestamp", Category: "SBOM", Description: "Validate SBOM timestamp field"},
	{Name: "sbom_tool", Category: "SBOM", Description: "Validate SBOM tool metadata"},
	{Name: "sbom_organization", Category: "SBOM", Description: "Validate SBOM organization metadata"},
	{Name: "sbom_spdxid", Category: "SBOM", Description: "Validate SPDX ID presence"},
	{Name: "sbom_schema_valid", Category: "SBOM", Description: "Validate SBOM against schema"},
	{Name: "sbom_parsable", Category: "SBOM", Description: "Ensure SBOM can be parsed successfully"},
	{Name: "sbom_machine_format", Category: "SBOM", Description: "Validate machine-readable SBOM format"},
	{Name: "sbom_sharable", Category: "SBOM", Description: "Validate SBOM sharability compliance"},

	// == SBOM: Specification & Format ==
	{Name: "sbom_spec", Category: "SBOM", Description: "Ensure SBOM specification is declared"},
	{Name: "sbom_spec_declared", Category: "SBOM", Description: "Validate SBOM specification declaration"},
	{Name: "sbom_spec_version", Category: "SBOM", Description: "Validate SBOM specification version"},
	{Name: "spec_with_version_compliant", Category: "SBOM", Description: "Validate SBOM spec version compliance"},
	{Name: "sbom_spec_file_format", Category: "SBOM", Description: "Validate SBOM specification file format"},
	{Name: "sbom_file_format", Category: "SBOM", Description: "Validate SBOM file format"},

	// == SBOM: Structure & Relationships ==
	{Name: "sbom_dependencies", Category: "SBOM", Description: "Validate SBOM dependency graph"},
	{Name: "sbom_depth", Category: "SBOM", Description: "Validate SBOM dependency depth"},
	{Name: "sbom_with_primary_component", Category: "SBOM", Description: "Validate SBOM has a primary component"},
	{Name: "sbom_primary_component", Category: "SBOM", Description: "Validate primary component details"},
	{Name: "sbom_with_uri", Category: "SBOM", Description: "Validate SBOM contains URI reference"},
	{Name: "sbom_uri", Category: "SBOM", Description: "Validate SBOM URI field"},
	{Name: "sbom_build", Category: "SBOM", Description: "Validate SBOM build metadata"},
	{Name: "sbom_build_process", Category: "SBOM", Description: "Validate SBOM build process information"},
	{Name: "sbom_with_bomlinks", Category: "SBOM", Description: "Validate presence of BOM links"},
	{Name: "sbom_bomlinks", Category: "SBOM", Description: "Validate SBOM BOM links section"},

	// == SBOM: Security ==
	{Name: "sbom_vulnerabilities", Category: "Security", Description: "Validate SBOM vulnerability section"},
	{Name: "sbom_with_vuln", Category: "Security", Description: "Validate SBOM contains vulnerability entries"},

	// == Component: Identity ==

	{Name: "comp_name", Category: "Component", Description: "Validate component name"},
	{Name: "comp_with_name", Category: "Component", Description: "Ensure component has a name"},
	{Name: "comp_version", Category: "Component", Description: "Validate component version"},
	{Name: "comp_with_version", Category: "Component", Description: "Ensure component has version"},
	{Name: "comp_supplier", Category: "Component", Description: "Validate component supplier"},
	{Name: "comp_with_supplier", Category: "Component", Description: "Ensure component supplier exists"},
	{Name: "comp_with_uniq_ids", Category: "Component", Description: "Ensure component has unique identifiers"},
	{Name: "comp_with_local_id", Category: "Component", Description: "Validate component local identifier"},
	{Name: "comp_purl", Category: "Component", Description: "Validate component PURL"},
	{Name: "comp_with_purl", Category: "Component", Description: "Ensure component has PURL"},
	{Name: "comp_cpe", Category: "Component", Description: "Validate component CPE"},
	{Name: "comp_with_cpe", Category: "Component", Description: "Ensure component has CPE"},
	{Name: "comp_purpose", Category: "Component", Description: "Validate component purpose field"},
	{Name: "comp_with_purpose", Category: "Component", Description: "Ensure component purpose exists"},
	{Name: "comp_with_primary_purpose", Category: "Component", Description: "Validate primary purpose designation"},

	// == Component: Structure & Relationships ==

	{Name: "comp_dependencies", Category: "Component", Description: "Validate component dependencies"},
	{Name: "comp_with_dependencies", Category: "Component", Description: "Ensure component dependency section exists"},
	{Name: "comp_depth", Category: "Component", Description: "Validate component dependency depth"},

	// == Component: Integrity & Checksums ==

	{Name: "comp_hash", Category: "Component", Description: "Validate component hash presence"},
	{Name: "comp_with_sha256", Category: "Component", Description: "Ensure component has SHA256 checksum"},
	{Name: "comp_hash_sha256", Category: "Component", Description: "Validate component SHA256 checksum"},
	{Name: "comp_with_checksums", Category: "Component", Description: "Ensure component has checksums"},
	{Name: "comp_with_checksums_sha256", Category: "Component", Description: "Ensure component has SHA256 checksum entry"},
	{Name: "comp_with_strong_checksums", Category: "Component", Description: "Validate component uses strong checksums"},
	{Name: "comp_with_weak_checksums", Category: "Component", Description: "Detect weak checksum algorithms"},
	{Name: "comp_source_hash", Category: "Component", Description: "Validate source code hash"},
	{Name: "comp_with_source_code_hash", Category: "Component", Description: "Ensure source code hash exists"},

	// == Component: Source & Executable ==

	{Name: "comp_with_source_code", Category: "Component", Description: "Ensure component references source code"},
	{Name: "comp_with_source_code_uri", Category: "Component", Description: "Validate source code URI"},
	{Name: "comp_with_executable_uri", Category: "Component", Description: "Validate executable URI"},

	// == License ==

	{Name: "comp_license", Category: "License", Description: "Validate component license presence"},
	{Name: "comp_with_licenses", Category: "License", Description: "Ensure component license section exists"},
	{Name: "comp_valid_licenses", Category: "License", Description: "Validate license identifiers"},
	{Name: "comp_with_valid_licenses", Category: "License", Description: "Ensure licenses are valid SPDX identifiers"},
	{Name: "comp_with_declared_license", Category: "License", Description: "Validate declared license"},
	{Name: "comp_with_concluded_license", Category: "License", Description: "Validate concluded license"},
	{Name: "comp_associated_license", Category: "License", Description: "Validate associated license"},
	{Name: "comp_with_associated_license", Category: "License", Description: "Ensure associated license exists"},
	{Name: "comp_with_deprecated_licenses", Category: "License", Description: "Detect deprecated licenses"},
	{Name: "comp_no_deprecated_licenses", Category: "License", Description: "Ensure no deprecated licenses are used"},
	{Name: "comp_with_restrictive_licenses", Category: "License", Description: "Detect restrictive licenses"},
	{Name: "comp_no_restrictive_licenses", Category: "License", Description: "Ensure no restrictive licenses are used"},

	// == Security — Vulnerabilities ==

	{Name: "comp_with_any_vuln_lookup_id", Category: "Security", Description: "Ensure component has vulnerability lookup ID"},
	{Name: "comp_with_multi_vuln_lookup_id", Category: "Security", Description: "Ensure component has multiple vulnerability lookup IDs"},
}

var featureLookup = make(map[string]Feature)

func init() {
	for _, f := range FeatureRegistry {
		featureLookup[f.Name] = f
	}
}
