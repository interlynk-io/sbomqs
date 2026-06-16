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
	"os"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/registry"
	"github.com/spf13/cobra"
)

const (
	featuresFileName = "features.yaml"
	features         = "features"
	comprehenssive   = "comprehenssive"
	comprFileName    = "compr.yaml"
	profiles         = "profiles"
	profFileName     = "profiles.yaml"
)

var generateFeaturesLegacy bool

// generateCmd represents the generate command for creating configuration files.
// It can generate YAML configs for features, comprehensive scoring, and profiles.
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "provides a comprehensive config generate for your sbom to get specific criteria",
	Example: `  sbomqs generate <argument>

 valid <argument> are comprehenssive, profiles, features

  # Generate config file for comprehenssive
  sbomqs generate comprehenssive

  # Generate config file for profiles
  sbomqs generate profiles

  # Generate config file for features
  sbomqs generate features

  # Generate legacy v1.x features config
  sbomqs generate features --legacy
`,

	RunE: func(_ *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())

		if len(args) > 0 {
			switch args[0] {
			case features:
				return generateYaml(ctx, generateFeaturesLegacy)
			case comprehenssive:
				return generateComprYaml(ctx)
			case profiles:
				return generateProfYaml(ctx)

			}
		} else {
			return fmt.Errorf("arguments missing%s", "list of valid command eg: profiles, comprehenssive, features")
		}
		return fmt.Errorf("invalid arguments%s", "list of valid command eg: profiles, comprehenssive, features")
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
	generateCmd.Flags().BoolVar(&generateFeaturesLegacy, "legacy", false, "generate legacy v1.x features configuration")
}

func generateYaml(_ context.Context, legacy bool) error {
	featuresConfig := registry.DefaultComprConfig()
	if legacy {
		featuresConfig = scorer.DefaultConfig()
	}

	if err := os.WriteFile(featuresFileName, []byte(featuresConfig), 0o600); err != nil {
		return err
	}
	fmt.Printf("Configuration written to %s\n", featuresFileName)
	return nil
}

func generateComprYaml(_ context.Context) error {
	if err := os.WriteFile(comprFileName, []byte(registry.DefaultComprConfig()), 0o600); err != nil {
		return err
	}
	fmt.Printf("Configuration written to %s\n", comprFileName)
	return nil
}

func generateProfYaml(_ context.Context) error {
	if err := os.WriteFile(profFileName, []byte(registry.DefaultProfConfig()), 0o600); err != nil {
		return err
	}
	fmt.Printf("Configuration written to %s\n", profFileName)
	return nil
}
