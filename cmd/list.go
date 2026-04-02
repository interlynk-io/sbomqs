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
	"github.com/interlynk-io/sbomqs/v2/pkg/list"
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
	Example: `  sbomqs list --feature <feature> [flags] <path-to-sbom-file>

  # Show all components with a supplier
  sbomqs list --feature comp_supplier my-app.spdx.json

  # Show components missing a supplier
  sbomqs list --feature comp_supplier --missing my-app.spdx.json

  # Show the actual supplier value for every component
  sbomqs list --feature comp_supplier --show my-app.spdx.json

  # Show components missing a version
  sbomqs list --feature comp_version --missing my-app.spdx.json

  # Show components with valid licenses
  sbomqs list --feature comp_valid_licenses my-app.spdx.json

  # Show components with invalid/missing licenses
  sbomqs list --feature comp_valid_licenses --missing my-app.spdx.json

  # Use a compliance profile (bsi = latest BSI v2.1)
  sbomqs list --profile bsi --feature comp_name my-app.cdx.json
  sbomqs list --profile ntia --feature comp_supplier --missing my-app.spdx.json
  sbomqs list --profile bsiv21 --feature comp_deployable_hash --missing my-app.cdx.json

  # Browse features supported by a profile
  sbomqs features --profile bsi
  sbomqs features --profile ntia

  All supported features: https://github.com/interlynk-io/sbomqs/blob/main/docs/commands/list.md#supported-features
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
	uCmd.profile = normalizeProfile(profile)

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

	listCmd.Flags().String("profile", "", "Compliance profile for feature extraction (e.g. bsi, bsiv21, bsiv11, bsiv20, fsct, ntia, interlynk). 'bsi' is an alias for the latest BSI version (bsiv21). Run 'sbomqs features --profile <profile>' to see supported features for each profile.")

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
	// Required: sbom-level
	"sbom_spec_version": {},
	"sbom_creator":      {},
	"sbom_timestamp":    {},

	// Additional: sbom-level
	"sbom_uri": {},

	// Required: component-level
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

	// Additional: component-level
	"comp_source_code_url":   {},
	"comp_download_url":      {},
	"comp_other_identifiers": {},
	"comp_original_licenses": {},

	// Optional: component-level
	"comp_effective_license": {},
	"comp_source_hash":       {},
	"comp_security_txt_url":  {},
}

// normalizeProfile resolves profile aliases to their canonical names.
// "bsi" is an alias for "bsiv21" (the latest BSI version).
func normalizeProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "bsi":
		return "bsiv21"
	default:
		return profile
	}
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

// profileSectionName maps a --profile value to the display section name used
// in ProfileSections. Used by the features command to filter by profile.
var profileSectionName = map[string]string{
	"bsiv11":    "BSI TR-03183-2 v1.1 (--profile bsiv11)",
	"bsiv20":    "BSI TR-03183-2 v2.0 (--profile bsiv20)",
	"bsiv21":    "BSI TR-03183-2 v2.1 (--profile bsiv21)",
	"ntia":      "NTIA Minimum Elements (--profile ntia)",
	"fsct":      "FSCT Framing 3rd Edition (--profile fsct)",
	"interlynk": "Interlynk (--profile interlynk)",
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
				"profile %q is not supported. Supported profiles: bsi (=bsiv21), bsiv11, bsiv20, bsiv21, fsct, ntia, interlynk",
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
		if _, ok := featureLookup[cleaned]; !ok && !list.IsKnownFeature(cleaned) {
			names := make([]string, 0, len(FeatureRegistry))
			for _, f := range FeatureRegistry {
				names = append(names, f.Name)
			}
			return fmt.Errorf(
				"feature %q is not supported.\n\nSupported features: %s",
				cleaned, strings.Join(names, ", "),
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
	{Name: "sbom_authors", Category: "SBOM", Description: "SBOM authors / creators"},
	{Name: "sbom_creation_timestamp", Category: "SBOM", Description: "SBOM creation timestamp"},
	{Name: "sbom_tool", Category: "SBOM", Description: "Tool that generated the SBOM (name + version)"},
	{Name: "sbom_organization", Category: "SBOM", Description: "SBOM producing organization"},
	{Name: "sbom_spdxid", Category: "SBOM", Description: "Document-level SPDX ID"},
	{Name: "sbom_schema_valid", Category: "SBOM", Description: "SBOM validates against its schema"},
	{Name: "sbom_parsable", Category: "SBOM", Description: "SBOM is syntactically parsable"},
	{Name: "sbom_sharable", Category: "SBOM", Description: "SBOM has a sharable data license"},

	// == SBOM: Specification & Format ==
	{Name: "sbom_spec", Category: "SBOM", Description: "SBOM specification type (cyclonedx / spdx)"},
	{Name: "sbom_spec_version", Category: "SBOM", Description: "SBOM specification version"},
	{Name: "sbom_spec_file_format", Category: "SBOM", Description: "SBOM file format (json / xml / tag-value)"},
	{Name: "spec_version_compliant", Category: "SBOM", Description: "Spec + version are compliant"},

	// == SBOM: Structure & Relationships ==
	{Name: "sbom_primary_comp", Category: "SBOM", Description: "Primary component name and version"},
	{Name: "sbom_primary_component", Category: "SBOM", Description: "Primary component declared"},
	{Name: "sbom_uri", Category: "SBOM", Description: "SBOM unique URI or namespace"},
	{Name: "sbom_dependencies", Category: "SBOM", Description: "SBOM dependency graph"},
	{Name: "sbom_build", Category: "SBOM", Description: "SBOM build / lifecycle metadata"},
	{Name: "sbom_bomlinks", Category: "SBOM", Description: "BOM-Link references present"},
	{Name: "sbom_supplier", Category: "SBOM", Description: "SBOM supplier (CycloneDX only)"},

	// == SBOM: Security ==
	{Name: "sbom_vuln", Category: "Security", Description: "SBOM contains vulnerability entries"},

	// == Component: Identity ==
	{Name: "comp_name", Category: "Component", Description: "Component name"},
	{Name: "comp_version", Category: "Component", Description: "Component version"},
	{Name: "comp_supplier", Category: "Component", Description: "Component supplier or manufacturer (with fallback)"},
	{Name: "comp_author", Category: "Component", Description: "Component authors (name, email)"},
	{Name: "comp_uniq_ids", Category: "Component", Description: "All unique identifiers: PURL, CPE, SWHID, SWID, OmniBOR"},
	{Name: "comp_local_id", Category: "Component", Description: "Component local identifier"},
	{Name: "comp_purl", Category: "Component", Description: "Component PURL"},
	{Name: "comp_cpe", Category: "Component", Description: "Component CPE"},
	{Name: "comp_primary_purpose", Category: "Component", Description: "Component primary purpose / type"},
	{Name: "comp_external_refs", Category: "Component", Description: "All external references (type: locator)"},

	// == Component: Structure & Relationships ==
	{Name: "comp_depth", Category: "Component", Description: "Direct dependency names, or 'leaf component' if none"},
	{Name: "comp_dependencies", Category: "Component", Description: "Component dependency declarations"},

	// == Component: Integrity & Checksums ==
	{Name: "comp_checksums", Category: "Component", Description: "Component has checksums"},
	{Name: "comp_sha256", Category: "Component", Description: "Component has SHA-256 checksum"},
	{Name: "comp_checksums_sha256", Category: "Component", Description: "Component has SHA-256 checksum entry"},
	{Name: "comp_strong_checksums", Category: "Component", Description: "Component uses strong checksum algorithms"},
	{Name: "comp_weak_checksums", Category: "Component", Description: "Component has weak checksum algorithms"},
	{Name: "comp_source_code_hash", Category: "Component", Description: "Source code hash"},

	// == Component: Source & Executable ==
	{Name: "comp_source_code_uri", Category: "Component", Description: "Component source code URI"},
	{Name: "comp_executable_uri", Category: "Component", Description: "Component executable / download URI"},

	// == License ==
	{Name: "comp_all_licenses", Category: "License", Description: "All licenses: concluded and declared, labeled by type"},
	{Name: "comp_licenses", Category: "License", Description: "Component has license expressions"},
	{Name: "comp_valid_licenses", Category: "License", Description: "Component licenses are valid SPDX identifiers"},
	{Name: "comp_associated_license", Category: "License", Description: "Component associated license"},
	{Name: "comp_concluded_license", Category: "License", Description: "Component concluded license"},
	{Name: "comp_declared_license", Category: "License", Description: "Component declared license"},
	{Name: "comp_deprecated_licenses", Category: "License", Description: "Component has deprecated licenses"},
	{Name: "comp_restrictive_licenses", Category: "License", Description: "Component has restrictive licenses"},

	// == Security — Vulnerabilities ==
	{Name: "comp_any_vuln_lookup_id", Category: "Security", Description: "Component has at least one vulnerability lookup ID"},
	{Name: "comp_multi_vuln_lookup_id", Category: "Security", Description: "Component has multiple vulnerability lookup IDs"},
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
