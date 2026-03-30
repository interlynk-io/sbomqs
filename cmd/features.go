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

	"github.com/spf13/cobra"
)

var featuresCmd = &cobra.Command{
	Use:   "features",
	Short: "List supported sbomqs features",
	Long:  "Displays all supported features grouped by profile section.",
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
	total := 0
	for _, s := range ProfileSections {
		total += len(s.Features)
	}

	fmt.Printf("Supported Features (%d total across %d sections):\n\n", total, len(ProfileSections))

	for _, section := range ProfileSections {
		fmt.Printf("%s:\n", section.Name)
		for _, f := range section.Features {
			fmt.Printf("  - %-35s %s\n", f.Name, f.Description)
		}
		fmt.Println()
	}
}

func printFeaturesJSON() error {
	type jsonSection struct {
		Name     string           `json:"name"`
		Features []ProfileFeature `json:"features"`
	}

	sections := make([]jsonSection, 0, len(ProfileSections))
	for _, s := range ProfileSections {
		sections = append(sections, jsonSection{
			Name:     s.Name,
			Features: s.Features,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(map[string]interface{}{
		"sections": sections,
	})
}
