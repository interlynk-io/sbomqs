// Copyright 2023 Interlynk.io
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
	"github.com/spf13/cobra"
)

const features_file_name = "features.yaml"
const features = "features"

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "provides a comprehensive config generate for your sbom to get specific criteria",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())

		if len(args) > 0 {
			if args[0] == features {
				return generateYaml(ctx)
			}
		} else {
			return fmt.Errorf(fmt.Sprintf("arguments missing%s", "list of valid command eg. features"))
		}
		return fmt.Errorf(fmt.Sprintf("invalid arguments%s", "list of valid command eg. features"))

	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

func generateYaml(ctx context.Context) error {
	return os.WriteFile(features_file_name, []byte(scorer.DefaultConfig()), 0755)
}
