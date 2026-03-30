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
	profile string

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

	profile, _ := cmd.Flags().GetString("profile")
	uCmd.profile = profile

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
		Path:        []string{uCmd.path},
		Features:    []string{uCmd.feature},
		Missing:     uCmd.missing,
		Basic:       uCmd.basic,
		JSON:        uCmd.json,
		Detailed:    uCmd.detailed,
		Color:       uCmd.color,
		Debug:       uCmd.debug,
		Show:        uCmd.show,
		ListProfile: uCmd.profile,
	}
}

func init() {
	rootCmd.AddCommand(listCmd)

	// -- Filter Control --
	listCmd.Flags().String("feature", "", "Filter by a supported feature (run 'sbomqs features' to list all)")
	_ = listCmd.MarkFlagRequired("feature")

	listCmd.Flags().BoolP("missing", "m", false, "List components or properties missing the specified feature")

	listCmd.Flags().String("profile", "", "Compliance profile for feature extraction (e.g. bsiv21, bsiv11, bsiv20, fsct, ntia, interlynk). When specified, only features relevant to the profile will be considered. Run 'sbomqs features --profile <profile>' to see supported features for each profile.")

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

// fsctFeatureKeys lists the feature keys supported by the fsct profile.
var fsctFeatureKeys = map[string]struct{}{
	// SBOM-level
	"sbom_provenance":        {},
	"sbom_primary_component": {},
	"relationships_coverage": {},
	// Component-level
	"comp_identity":        {},
	"supplier_attribution": {},
	"comp_unique_id":       {},
	"artifact_integrity":   {},
	"license_coverage":     {},
	"copyright_coverage":   {},
}

// ntiaFeatureKeys lists the feature keys supported by the ntia profile.
var ntiaFeatureKeys = map[string]struct{}{
	// SBOM-level
	"sbom_authors":       {},
	"sbom_relationships": {},
	"sbom_timestamp":     {},
	// Component-level
	"comp_supplier": {},
	"comp_name":     {},
	"comp_version":  {},
	"comp_uniq_id":  {},
}

// bsiV11FeatureKeys lists the feature keys supported by the bsiv11 profile.
var bsiV11FeatureKeys = map[string]struct{}{
	// SBOM-level
	"sbom_creator":   {},
	"sbom_timestamp": {},
	"sbom_uri":       {},
	// Required: component-level
	"comp_creator": {},
	"comp_name":    {},
	"comp_version": {},
	"comp_depth":   {},
	"comp_license": {},
	"comp_hash":    {},
	// Additional: component-level
	"comp_unique_identifiers": {},
	"comp_source_url":         {},
	"comp_executable_url":     {},
	"comp_source_hash":        {},
}

// bsiV20FeatureKeys lists the feature keys supported by the bsiv20 profile.
var bsiV20FeatureKeys = map[string]struct{}{
	// SBOM-level
	"sbom_creator":   {},
	"sbom_timestamp": {},
	"sbom_uri":       {},
	// Required: component-level
	"comp_creator":             {},
	"comp_name":                {},
	"comp_version":             {},
	"comp_filename":            {},
	"comp_depth":               {},
	"comp_associated_license":  {},
	"comp_deployable_hash":     {},
	"comp_executable_property": {},
	"comp_archive_property":    {},
	"comp_structured_property": {},
	// Additional: component-level
	"comp_source_code_url":   {},
	"comp_download_url":      {},
	"comp_other_identifiers": {},
	"comp_concluded_license": {},
	// Optional: component-level
	"comp_declared_license": {},
	"comp_source_hash":      {},
}

// interlynkFeatureKeys lists the feature keys supported by the interlynk profile.
var interlynkFeatureKeys = map[string]struct{}{
	// Identification
	"comp_name":     {},
	"comp_version":  {},
	"comp_local_id": {},
	// Provenance
	"sbom_timestamp": {},
	"sbom_authors":   {},
	"sbom_tool":      {},
	"sbom_supplier":  {},
	"sbom_namespace": {},
	"sbom_lifecycle": {},
	// Integrity
	"comp_checksums": {},
	"comp_sha256":    {},
	"sbom_signature": {},
	// Completeness
	"comp_dependencies":      {},
	"sbom_completeness":      {},
	"sbom_primary_component": {},
	"comp_source_code":       {},
	"comp_supplier":          {},
	"comp_purpose":           {},
	// Licensing
	"comp_licenses":                {},
	"comp_valid_licenses":          {},
	"comp_no_deprecated_licenses":  {},
	"comp_no_restrictive_licenses": {},
	"comp_declared_licenses":       {},
	"sbom_data_license":            {},
	// Vulnerability
	"comp_purl": {},
	"comp_cpe":  {},
	// Structural
	"sbom_spec_declared": {},
	"sbom_spec_version":  {},
	"sbom_file_format":   {},
	"sbom_schema_valid":  {},
}

// bsiV21FeatureKeys lists the feature keys supported by the bsiv21 profile.
var bsiV21FeatureKeys = map[string]struct{}{
	"sbom_spec_version":         {},
	"sbom_creator":              {},
	"sbom_timestamp":            {},
	"sbom_uri":                  {},
	"comp_creator":              {},
	"comp_name":                 {},
	"comp_version":              {},
	"comp_filename":             {},
	"comp_depth":                {},
	"comp_distribution_license": {},
	"comp_deployable_hash":      {},
	"comp_executable_prop":      {},
	"comp_archive_prop":         {},
	"comp_structured_prop":      {},
	"comp_source_code_url":      {},
	"comp_download_url":         {},
	"comp_other_identifiers":    {},
	"comp_original_licenses":    {},
	"comp_effective_license":    {},
	"comp_source_hash":          {},
	"comp_security_txt_url":     {},
}

// supportedProfiles lists the known profile values for --profile.
var supportedProfiles = map[string]struct{}{
	"fsct":      {},
	"ntia":      {},
	"bsiv11":    {},
	"bsiv20":    {},
	"bsiv21":    {},
	"interlynk": {},
}

func validateparsedListCmd(uCmd *userListCmd) error {
	// Check path
	if len(uCmd.path) == 0 {
		return errors.New("path is required")
	}

	// Validate profile if given
	if uCmd.profile != "" {
		if _, ok := supportedProfiles[uCmd.profile]; !ok {
			return fmt.Errorf(
				"profile %q is not supported. Supported profiles: fsct, ntia, bsiv11, bsiv20, bsiv21, interlynk",
				uCmd.profile,
			)
		}
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

	// When a profile is given, validate against that profile's feature set.
	// When no profile is given, validate against the generic feature registry.
	switch uCmd.profile {
	case "fsct":
		if _, ok := fsctFeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: sbom_provenance, sbom_primary_component, relationships_coverage, comp_identity, supplier_attribution, comp_unique_id, artifact_integrity, license_coverage, copyright_coverage",
				cleaned, uCmd.profile,
			)
		}
	case "ntia":
		if _, ok := ntiaFeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: sbom_authors, sbom_relationships, sbom_timestamp, comp_supplier, comp_name, comp_version, comp_uniq_id",
				cleaned, uCmd.profile,
			)
		}
	case "bsiv11":
		if _, ok := bsiV11FeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: sbom_creator, sbom_timestamp, sbom_uri, comp_creator, comp_name, comp_version, comp_depth, comp_license, comp_hash, comp_unique_identifiers, comp_source_url, comp_executable_url, comp_source_hash",
				cleaned, uCmd.profile,
			)
		}
	case "bsiv20":
		if _, ok := bsiV20FeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: sbom_creator, sbom_timestamp, sbom_uri, comp_creator, comp_name, comp_version, comp_filename, comp_depth, comp_associated_license, comp_deployable_hash, comp_executable_property, comp_archive_property, comp_structured_property, comp_source_code_url, comp_download_url, comp_other_identifiers, comp_concluded_license, comp_declared_license, comp_source_hash",
				cleaned, uCmd.profile,
			)
		}
	case "bsiv21":
		if _, ok := bsiV21FeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: sbom_spec_version, sbom_creator, sbom_timestamp, sbom_uri, comp_creator, comp_name, comp_version, comp_filename, comp_depth, comp_distribution_license, comp_deployable_hash, comp_executable_prop, comp_archive_prop, comp_structured_prop, comp_source_code_url, comp_download_url, comp_other_identifiers, comp_original_licenses, comp_effective_license, comp_source_hash, comp_security_txt_url",
				cleaned, uCmd.profile,
			)
		}
	case "interlynk":
		if _, ok := interlynkFeatureKeys[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported for profile %q.\n\nSupported features: comp_name, comp_version, comp_local_id, sbom_timestamp, sbom_authors, sbom_tool, sbom_supplier, sbom_namespace, sbom_lifecycle, comp_checksums, comp_sha256, sbom_signature, comp_dependencies, sbom_completeness, sbom_primary_component, comp_source_code, comp_supplier, comp_purpose, comp_licenses, comp_valid_licenses, comp_no_deprecated_licenses, comp_no_restrictive_licenses, comp_declared_licenses, sbom_data_license, comp_purl, comp_cpe, sbom_spec_declared, sbom_spec_version, sbom_file_format, sbom_schema_valid",
				cleaned, uCmd.profile,
			)
		}
	default:
		if _, ok := featureLookup[cleaned]; !ok {
			return fmt.Errorf(
				"feature %q is not supported.\n\nRun \"sbomqs features\" to see supported features.",
				cleaned,
			)
		}
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
	{Name: "sbom_primary_comp", Category: "SBOM", Description: "Show primary component name and version"},
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

	{Name: "comp_name", Category: "Component", Description: "Show component name"},
	{Name: "comp_with_name", Category: "Component", Description: "Ensure component has a name"},
	{Name: "comp_version", Category: "Component", Description: "Show component version"},
	{Name: "comp_with_version", Category: "Component", Description: "Ensure component has version"},
	{Name: "comp_supplier", Category: "Component", Description: "Show component supplier or manufacturer"},
	{Name: "comp_with_supplier", Category: "Component", Description: "Ensure component supplier exists"},
	{Name: "comp_author", Category: "Component", Description: "Show component authors (name, email)"},
	{Name: "comp_with_uniq_ids", Category: "Component", Description: "Show all unique identifiers (PURL, CPE, SWHID, SWID, OmniBOR)"},
	{Name: "comp_with_local_id", Category: "Component", Description: "Show component local identifier"},
	{Name: "comp_purl", Category: "Component", Description: "Show component PURL"},
	{Name: "comp_with_purl", Category: "Component", Description: "Ensure component has PURL"},
	{Name: "comp_cpe", Category: "Component", Description: "Show component CPE"},
	{Name: "comp_with_cpe", Category: "Component", Description: "Ensure component has CPE"},
	{Name: "comp_purpose", Category: "Component", Description: "Show component purpose field"},
	{Name: "comp_with_purpose", Category: "Component", Description: "Ensure component purpose exists"},
	{Name: "comp_with_primary_purpose", Category: "Component", Description: "Validate primary purpose designation"},
	{Name: "comp_external_refs", Category: "Component", Description: "Show all external references (type: locator)"},

	// == Component: Structure & Relationships ==

	{Name: "comp_dependencies", Category: "Component", Description: "Validate component dependencies"},
	{Name: "comp_with_dependencies", Category: "Component", Description: "Ensure component dependency section exists"},
	{Name: "comp_depth", Category: "Component", Description: "Show direct dependencies by name, or 'leaf component' if none"},

	// == Component: Integrity & Checksums ==

	{Name: "comp_hash", Category: "Component", Description: "Show component hash value"},
	{Name: "comp_with_sha256", Category: "Component", Description: "Ensure component has SHA256 checksum"},
	{Name: "comp_hash_sha256", Category: "Component", Description: "Show component SHA256 checksum"},
	{Name: "comp_with_checksums", Category: "Component", Description: "Ensure component has checksums"},
	{Name: "comp_with_checksums_sha256", Category: "Component", Description: "Ensure component has SHA256 checksum entry"},
	{Name: "comp_with_strong_checksums", Category: "Component", Description: "Validate component uses strong checksums"},
	{Name: "comp_with_weak_checksums", Category: "Component", Description: "Detect weak checksum algorithms"},
	{Name: "comp_source_hash", Category: "Component", Description: "Show source code hash"},
	{Name: "comp_with_source_code_hash", Category: "Component", Description: "Ensure source code hash exists"},

	// == Component: Source & Executable ==

	{Name: "comp_with_source_code", Category: "Component", Description: "Ensure component references source code"},
	{Name: "comp_with_source_code_uri", Category: "Component", Description: "Show source code URI"},
	{Name: "comp_with_executable_uri", Category: "Component", Description: "Show executable URI"},

	// == License ==

	{Name: "comp_license", Category: "License", Description: "Show all component licenses (concluded and declared)"},
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

// ProfileFeature is a feature entry within a profile section for display purposes.
type ProfileFeature struct {
	Name        string
	Description string
}

// ProfileSection groups features under a named profile or "Generic" for display.
type ProfileSection struct {
	Name     string
	Features []ProfileFeature
}

// ProfileSections defines all sections shown by `sbomqs features`, ordered:
// Generic first, then each compliance profile alphabetically.
var ProfileSections = []ProfileSection{
	{
		Name: "Generic (no --profile required)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_authors", Description: "SBOM authors"},
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			{Name: "sbom_tool", Description: "Tool that generated the SBOM (name + version)"},
			{Name: "sbom_spec", Description: "SBOM specification type (cyclonedx / spdx)"},
			{Name: "sbom_spec_version", Description: "SBOM specification version"},
			{Name: "sbom_file_format", Description: "SBOM file format (json / xml / tag-value)"},
			{Name: "sbom_uri", Description: "SBOM unique URI or namespace"},
			{Name: "sbom_primary_comp", Description: "Primary component name and version"},
			{Name: "sbom_schema_valid", Description: "Whether the SBOM validates against its schema"},
			{Name: "sbom_dependencies", Description: "SBOM-level dependency graph summary"},
			{Name: "sbom_organization", Description: "SBOM organization metadata"},
			{Name: "sbom_build", Description: "SBOM build / lifecycle metadata"},
			{Name: "sbom_with_vuln", Description: "Whether the SBOM contains vulnerability entries"},
			// Component-level
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_supplier", Description: "Component supplier or manufacturer (fallback)"},
			{Name: "comp_author", Description: "Component authors (name, email)"},
			{Name: "comp_external_refs", Description: "All external references (type: locator)"},
			{Name: "comp_license", Description: "All licenses: concluded and declared, labeled by type"},
			{Name: "comp_depth", Description: "Direct dependencies by name, or 'leaf component' if none"},
			{Name: "comp_with_uniq_ids", Description: "All unique identifiers: PURL, CPE, SWHID, SWID, OmniBOR"},
			{Name: "comp_purl", Description: "Component PURL"},
			{Name: "comp_cpe", Description: "Component CPE"},
			{Name: "comp_hash", Description: "Component checksum value"},
			{Name: "comp_purpose", Description: "Component purpose / type"},
			{Name: "comp_with_source_code_uri", Description: "Component source code URI"},
			{Name: "comp_with_executable_uri", Description: "Component executable / download URI"},
			{Name: "comp_source_hash", Description: "Source code hash"},
		},
	},
	{
		Name: "BSI TR-03183-2 v1.1 (--profile bsiv11)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_creator", Description: "SBOM creator contact (email or URL)"},
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			{Name: "sbom_uri", Description: "SBOM URI"},
			// Component-level — required
			{Name: "comp_creator", Description: "Component creator contact (email or URL)"},
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_depth", Description: "Dependency relationships"},
			{Name: "comp_license", Description: "License (concluded preferred, declared fallback)"},
			{Name: "comp_hash", Description: "Component hash (any algorithm)"},
			// Component-level — additional
			{Name: "comp_unique_identifiers", Description: "Unique identifiers (PURL, CPE)"},
			{Name: "comp_source_url", Description: "Source code URL"},
			{Name: "comp_executable_url", Description: "Executable / download URL"},
			{Name: "comp_source_hash", Description: "Source code hash"},
		},
	},
	{
		Name: "BSI TR-03183-2 v2.0 (--profile bsiv20)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_creator", Description: "SBOM creator contact (email or URL)"},
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			{Name: "sbom_uri", Description: "SBOM URI"},
			// Component-level — required
			{Name: "comp_creator", Description: "Component creator contact (email or URL)"},
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_filename", Description: "Component filename"},
			{Name: "comp_depth", Description: "Dependency relationships"},
			{Name: "comp_associated_license", Description: "Associated license (concluded preferred, declared fallback)"},
			{Name: "comp_deployable_hash", Description: "Deployable component hash"},
			{Name: "comp_executable_property", Description: "Executable property"},
			{Name: "comp_archive_property", Description: "Archive property"},
			{Name: "comp_structured_property", Description: "Structured property"},
			// Component-level — additional
			{Name: "comp_source_code_url", Description: "Source code URL"},
			{Name: "comp_download_url", Description: "Download / executable URL"},
			{Name: "comp_other_identifiers", Description: "Other unique identifiers (PURL, CPE)"},
			{Name: "comp_concluded_license", Description: "Concluded license"},
			// Component-level — optional
			{Name: "comp_declared_license", Description: "Declared license"},
			{Name: "comp_source_hash", Description: "Source code hash"},
		},
	},
	{
		Name: "BSI TR-03183-2 v2.1 (--profile bsiv21)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_spec_version", Description: "SBOM specification version (CycloneDX ≥ 1.6)"},
			{Name: "sbom_creator", Description: "SBOM creator contact (email or URL)"},
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			{Name: "sbom_uri", Description: "SBOM URI"},
			// Component-level — required
			{Name: "comp_creator", Description: "Component creator contact (email or URL)"},
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_filename", Description: "Component filename"},
			{Name: "comp_depth", Description: "Dependency relationships"},
			{Name: "comp_distribution_license", Description: "Distribution license (concluded)"},
			{Name: "comp_deployable_hash", Description: "Deployable component hash"},
			{Name: "comp_executable_prop", Description: "Executable property"},
			{Name: "comp_archive_prop", Description: "Archive property"},
			{Name: "comp_structured_prop", Description: "Structured property"},
			// Component-level — additional
			{Name: "comp_source_code_url", Description: "Source code URL"},
			{Name: "comp_download_url", Description: "Download / executable URL"},
			{Name: "comp_other_identifiers", Description: "Other unique identifiers (PURL, CPE, SWID)"},
			{Name: "comp_original_licenses", Description: "Original / declared licenses"},
			{Name: "comp_effective_license", Description: "Effective license"},
			// Component-level — optional
			{Name: "comp_source_hash", Description: "Source code hash"},
			{Name: "comp_security_txt_url", Description: "security.txt URL"},
		},
	},
	{
		Name: "FSCT Framing 3rd Edition (--profile fsct)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_provenance", Description: "SBOM provenance (author or tool declared)"},
			{Name: "sbom_primary_component", Description: "Primary component declared"},
			{Name: "relationships_coverage", Description: "Dependency relationship completeness"},
			// Component-level
			{Name: "comp_identity", Description: "Component name and version"},
			{Name: "supplier_attribution", Description: "Supplier attribution (name, URL, email, or unknown)"},
			{Name: "comp_unique_id", Description: "Unique identifier (PURL, CPE, SWHID, SWID, or OmniBOR)"},
			{Name: "artifact_integrity", Description: "Component hash (any algorithm)"},
			{Name: "license_coverage", Description: "License information (any type)"},
			{Name: "copyright_coverage", Description: "Copyright text"},
		},
	},
	{
		Name: "Interlynk (--profile interlynk)",
		Features: []ProfileFeature{
			// Identification
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_local_id", Description: "Component local identifier"},
			// Provenance
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			{Name: "sbom_authors", Description: "SBOM authors"},
			{Name: "sbom_tool", Description: "SBOM tool name and version"},
			{Name: "sbom_supplier", Description: "SBOM supplier"},
			{Name: "sbom_namespace", Description: "SBOM namespace / URI"},
			{Name: "sbom_lifecycle", Description: "SBOM lifecycle / build stage"},
			// Integrity
			{Name: "comp_checksums", Description: "Component checksums (any algorithm)"},
			{Name: "comp_sha256", Description: "Component SHA-256 checksum"},
			{Name: "sbom_signature", Description: "SBOM signature"},
			// Completeness
			{Name: "comp_dependencies", Description: "Component dependency declarations"},
			{Name: "sbom_completeness", Description: "SBOM completeness declaration"},
			{Name: "sbom_primary_component", Description: "Primary component declared"},
			{Name: "comp_source_code", Description: "Component source code reference"},
			{Name: "comp_supplier", Description: "Component supplier"},
			{Name: "comp_purpose", Description: "Component purpose / type"},
			// Licensing
			{Name: "comp_licenses", Description: "Component licenses (concluded)"},
			{Name: "comp_valid_licenses", Description: "Component licenses are valid SPDX identifiers"},
			{Name: "comp_no_deprecated_licenses", Description: "No deprecated licenses"},
			{Name: "comp_no_restrictive_licenses", Description: "No restrictive licenses"},
			{Name: "comp_declared_licenses", Description: "Component declared licenses"},
			{Name: "sbom_data_license", Description: "SBOM data license"},
			// Vulnerability
			{Name: "comp_purl", Description: "Component PURL"},
			{Name: "comp_cpe", Description: "Component CPE"},
			// Structural
			{Name: "sbom_spec_declared", Description: "SBOM specification declared"},
			{Name: "sbom_spec_version", Description: "SBOM specification version"},
			{Name: "sbom_file_format", Description: "SBOM file format"},
			{Name: "sbom_schema_valid", Description: "SBOM schema valid"},
		},
	},
	{
		Name: "NTIA Minimum Elements (--profile ntia)",
		Features: []ProfileFeature{
			// SBOM-level
			{Name: "sbom_authors", Description: "SBOM author declared"},
			{Name: "sbom_relationships", Description: "Primary component dependency relationships"},
			{Name: "sbom_timestamp", Description: "SBOM creation timestamp"},
			// Component-level
			{Name: "comp_supplier", Description: "Component supplier"},
			{Name: "comp_name", Description: "Component name"},
			{Name: "comp_version", Description: "Component version"},
			{Name: "comp_uniq_id", Description: "Unique identifier (PURL or CPE)"},
		},
	},
}
