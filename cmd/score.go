// Copyright 2025 Interlynk.io
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
	"log"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/samber/lo"

	"github.com/spf13/cobra"
)

var (
	inFile       string
	inDirPath    string
	category     string
	feature      string
	reportFormat string
	configPath   string
)

type userCmd struct {
	// input control
	path []string

	// filter control
	categories []string
	features   []string

	// output control
	json     bool
	basic    bool
	detailed bool
	color    bool

	// directory control
	recurse bool

	// debug control
	debug bool

	// config control
	configPath string

	signature string
	publicKey string

	// profiles
	profile []string

	// Old scoring
	legacy bool
}

// scoreCmd represents the score command
var scoreCmd = &cobra.Command{
	Use:          "score",
	Short:        "comprehensive quality score for your sbom",
	SilenceUsage: true,
	Example: ` sbomqs score [--category <category>] [--feature <feature>]  [--basic|--json]  <SBOM file>

  # Get a score against a SBOM in a table output
  sbomqs score samples/sbomqs-spdx-syft.json

  # Get a score against a SBOM in a basic output
  sbomqs score --basic samples/sbomqs-spdx-syft.json

  # Get a score against a SBOM in a JSON output
  sbomqs score --json samples/sbomqs-spdx-syft.json

  # Get a score for a 'BSI TR-03183-2 v1.1' category against a SBOM in a table output
  sbomqs score -c bsi-v1.1 samples/sbomqs-spdx-syft.json

  # Get a score for a 'BSI TR-03183-2 v2.0' category against a SBOM in a table output
  sbomqs score -c bsi-v2.0 samples/sbomqs-spdx-syft.json

  # To verify signature of a SBOM, use the --sig and --pub flags
  sbomqs score -c bsi-v2.0 --sig samples/signature-test-data/sbom.sig --pub samples/signature-test-data/public_key.pem samples/signature-test-data/SPDXJSONExample-v2.3.spdx.json
 
  # Get a score for a 'NTIA-minimum-elements' category against a SBOM in a table output
  sbomqs score --category NTIA-minimum-elements samples/sbomqs-spdx-syft.json

  # Get a score for a 'NTIA-minimum-elements' category and 'sbom_authors' feature against a SBOM in a table output
  sbomqs score --category NTIA-minimum-elements --feature sbom_authors samples/sbomqs-spdx-syft.json

  # Get  a score for multiple features
  sbomqs score --feature comp_with_name,comp_with_uniq_ids,sbom_authors,sbom_creation_timestamp  samples/sbomqs-spdx-syft.json 

  # Get a score for multiple categories
  sbomqs score --category NTIA-minimum-elements or ntia,bsi-v1.1,bsi-v2.0,Structural,Semantic,Sharing,Quality   samples/sbomqs-spdx-syft.json
`,

	Args: func(_ *cobra.Command, args []string) error {
		if len(args) <= 0 {
			if len(inFile) <= 0 && len(inDirPath) <= 0 {
				return fmt.Errorf("provide a path to an sbom file or directory of sbom files")
			}
		}
		return nil
	},
	RunE: processScore,
}

var categoryAliases = map[string]string{
	"ntia":                  "NTIA-minimum-elements",
	"NTIA":                  "NTIA-minimum-elements",
	"ntia-minimum-elements": "NTIA-minimum-elements",
	"structural":            "Structural",
	"sharing":               "Sharing",
	"semantic":              "Semantic",
	"quality":               "Quality",
}

func processScore(cmd *cobra.Command, args []string) error {
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
	err := validateEngineParams(ctx, engParams)
	if err != nil {
		return fmt.Errorf("failed to validate engine params: %w", err)
	}

	return engine.Run(ctx, engParams)
}

func validateEngineParams(ctx context.Context, ep *engine.Params) error {
	log := logger.FromContext(ctx)
	log.Debug("validating engine parameters")

	validPaths := validatePaths(ctx, ep.Path)
	if len(validPaths) == 0 {
		return fmt.Errorf("no valid paths provided")
	}
	ep.Path = validPaths

	if ep.ConfigPath != "" {
		if _, err := os.Stat(ep.ConfigPath); err != nil {
			return fmt.Errorf("invalid config path: %s: %w", ep.ConfigPath, err)
		}
	}

	ep.Categories = removeEmptyStrings(ep.Categories)
	ep.Features = removeEmptyStrings(ep.Features)

	return nil
}

func removeEmptyStrings(input []string) []string {
	var result []string
	for _, s := range input {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// validatePaths returns the valid paths.
func validatePaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debug("validating paths")
	var validPaths []string
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			log.Debugf("skipping invalid path: %s, error: %v", path, err)
			continue
		}
		validPaths = append(validPaths, path)
	}
	return validPaths
}

func toUserCmd(cmd *cobra.Command, args []string) *userCmd {
	uCmd := &userCmd{}

	// input control
	if len(args) <= 0 {
		if len(inFile) > 0 {
			uCmd.path = append(uCmd.path, inFile)
		}

		if len(inDirPath) > 0 {
			uCmd.path = append(uCmd.path, inDirPath)
		}
	} else {
		uCmd.path = append(uCmd.path, args[0:]...)
	}

	// config control
	if configPath == "" {
		uCmd.configPath, _ = cmd.Flags().GetString("configpath")
	} else {
		uCmd.configPath = configPath
	}
	// filter control
	if category == "" {
		c, _ := cmd.Flags().GetString("category")
		cList := strings.Split(c, ",")
		for i, val := range cList {
			if fullName, ok := categoryAliases[val]; ok {
				cList[i] = fullName
			} else {
				cList[i] = val
			}
		}
		uCmd.categories = cList
	}

	if feature == "" {
		f, _ := cmd.Flags().GetString("feature")
		uCmd.features = strings.Split(f, ",")
	}

	// output control
	uCmd.json, _ = cmd.Flags().GetBool("json")
	uCmd.basic, _ = cmd.Flags().GetBool("basic")
	uCmd.detailed, _ = cmd.Flags().GetBool("detailed")
	uCmd.color, _ = cmd.Flags().GetBool("color")
	uCmd.signature, _ = cmd.Flags().GetString("sig")
	uCmd.publicKey, _ = cmd.Flags().GetString("pub")
	uCmd.legacy, _ = cmd.Flags().GetBool("legacy")
	uCmd.profile, _ = cmd.Flags().GetStringSlice("profile")

	if reportFormat != "" {
		uCmd.json = strings.ToLower(reportFormat) == "json"
		uCmd.basic = strings.ToLower(reportFormat) == "basic"
		uCmd.detailed = strings.ToLower(reportFormat) == "detailed"
	}

	// debug control
	uCmd.debug, _ = cmd.Flags().GetBool("debug")

	return uCmd
}

func toEngineParams(uCmd *userCmd) *engine.Params {
	return &engine.Params{
		Path:       uCmd.path,
		Categories: uCmd.categories,
		Features:   uCmd.features,
		JSON:       uCmd.json,
		Basic:      uCmd.basic,
		Detailed:   uCmd.detailed,
		Color:      uCmd.color,
		Recurse:    uCmd.recurse,
		Debug:      uCmd.debug,
		ConfigPath: uCmd.configPath,
		Signature:  uCmd.signature,
		PublicKey:  uCmd.publicKey,
		Legacy:     uCmd.legacy,
		Profiles:   uCmd.profile,
	}
}

func validatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}

func validateFlags(cmd *userCmd) error {
	if cmd.configPath != "" {
		if err := validatePath(cmd.configPath); err != nil {
			return fmt.Errorf("invalid config path: %w", err)
		}
	}

	if len(reportFormat) > 0 && !lo.Contains(reporter.ReportFormats, reportFormat) {
		return fmt.Errorf("invalid report format: %s", reportFormat)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(scoreCmd)

	// Config Control
	scoreCmd.Flags().StringP("configpath", "", "", "scoring based on config path")

	// Filter Control
	scoreCmd.Flags().StringP("category", "c", "", "filter by category (e.g. 'bsi-v1', 'NTIA-minimum-elements', 'Quality', 'Semantic', 'Sharing', 'Structural')")
	scoreCmd.Flags().StringP("feature", "f", "", "filter by feature (e.g. 'sbom_authors',  'comp_with_name', 'sbom_creation_timestamp') ")

	// Spec Control
	scoreCmd.Flags().BoolP("spdx", "", false, "limit scoring to spdx sboms")
	scoreCmd.Flags().BoolP("cdx", "", false, "limit scoring to cdx sboms")
	scoreCmd.MarkFlagsMutuallyExclusive("spdx", "cdx")
	err := scoreCmd.Flags().MarkHidden("spdx")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}
	err = scoreCmd.Flags().MarkHidden("cdx")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}

	// Directory Control
	scoreCmd.Flags().BoolP("recurse", "r", false, "recurse into subdirectories")
	err = scoreCmd.Flags().MarkHidden("recurse")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}

	// Output Control
	scoreCmd.Flags().BoolP("json", "j", false, "results in json")
	scoreCmd.Flags().BoolP("detailed", "d", false, "results in table format, default")
	scoreCmd.Flags().BoolP("basic", "b", false, "results in single line format")
	scoreCmd.Flags().BoolP("color", "l", false, "output in colorful")

	// Debug Control
	scoreCmd.Flags().BoolP("debug", "D", false, "enable debug logging")

	// Deprecated
	scoreCmd.Flags().StringVar(&inFile, "filepath", "", "sbom file path")
	scoreCmd.Flags().StringVar(&inDirPath, "dirpath", "", "sbom dir path")
	scoreCmd.MarkFlagsMutuallyExclusive("filepath", "dirpath")
	scoreCmd.Flags().StringVar(&reportFormat, "reportFormat", "", "reporting format basic/detailed/json")
	err = scoreCmd.Flags().MarkDeprecated("reportFormat", "use --json, --detailed, or --basic instead")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}
	err = scoreCmd.Flags().MarkDeprecated("filepath", "use positional argument instead")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}
	err = scoreCmd.Flags().MarkDeprecated("dirpath", "use positional argument instead")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}
	err = scoreCmd.Flags().MarkDeprecated("dirpath", "use positional argument instead")
	if err != nil {
		// Handle the error appropriately, such as logging it or returning it
		log.Fatalf("Failed to mark flag as deprecated: %v", err)
	}

	scoreCmd.Flags().StringP("sig", "v", "", "signature of sbom")
	scoreCmd.Flags().StringP("pub", "p", "", "public key of sbom")

	scoreCmd.Flags().StringSlice("profile", nil, "Profiles to run (comma-separated or repeatable)")
	scoreCmd.Flags().BoolP("legacy", "e", false, "legacy")
}
