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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
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

// generateCmd represents the generate command
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
`,

	RunE: func(_ *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())

		if len(args) > 0 {
			switch args[0] {
			case features:
				return generateYaml(ctx)
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
}

func generateYaml(_ context.Context) error {
	return os.WriteFile(featuresFileName, []byte(scorer.DefaultConfig()), 0o600)
}

func generateComprYaml(_ context.Context) error {
	return os.WriteFile(comprFileName, []byte(registry.DefaultComprConfig()), 0o600)
}

func generateProfYaml(_ context.Context) error {
	return os.WriteFile(profFileName, []byte(registry.DefaultProfConfig()), 0o600)
}
