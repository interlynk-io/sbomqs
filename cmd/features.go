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
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

var featuresCmd = &cobra.Command{
	Use:   "features",
	Short: "List supported sbomqs features",
	Long:  "Displays all supported features grouped by category.",
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOutput, _ := cmd.Flags().GetBool("json")

		if jsonOutput {
			return printFeaturesJSON()
		}

		printFeaturesHuman()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(featuresCmd)

	featuresCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
}

func printFeaturesHuman() {
	grouped := make(map[string][]Feature)

	for _, f := range FeatureRegistry {
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	// Sort categories
	var categories []string
	for cat := range grouped {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	total := len(FeatureRegistry)
	fmt.Printf("Supported Features (%d total):\n\n", total)

	for _, cat := range categories {
		features := grouped[cat]

		// Sort features inside category
		sort.Slice(features, func(i, j int) bool {
			return features[i].Name < features[j].Name
		})

		fmt.Printf("%s:\n", cat)
		for _, f := range features {
			fmt.Printf("  - %-30s %s\n", f.Name, f.Description)
		}
		fmt.Println()
	}
}

func printFeaturesJSON() error {
	grouped := make(map[string][]Feature)

	for _, f := range FeatureRegistry {
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	// Optional: sort features per category for stable output
	for _, features := range grouped {
		sort.Slice(features, func(i, j int) bool {
			return features[i].Name < features[j].Name
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(map[string]interface{}{
		"total":      len(FeatureRegistry),
		"categories": grouped,
	})
}
