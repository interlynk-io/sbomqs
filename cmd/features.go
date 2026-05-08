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
	"strings"

	"github.com/spf13/cobra"
)

var featuresCmd = &cobra.Command{
	Use:   "features",
	Short: "List supported sbomqs features",
	Long:  "Displays all supported features grouped by profile section.",
	Example: `  # Show all features across all profiles
  sbomqs features

  # Show features for a specific profile
  sbomqs features --profile bsi        # latest BSI (bsiv21)
  sbomqs features --profile bsiv21
  sbomqs features --profile ntia
  sbomqs features --profile interlynk

  # JSON output
  sbomqs features --json
  sbomqs features --profile fsct --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		profile, _ := cmd.Flags().GetString("profile")
		profile = normalizeProfile(strings.TrimSpace(strings.ToLower(profile)))

		sections, err := resolveSections(profile)
		if err != nil {
			return err
		}

		if jsonOutput {
			return printFeaturesJSON(sections)
		}

		printFeaturesHuman(sections, profile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(featuresCmd)

	featuresCmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	featuresCmd.Flags().String("profile", "", "Show features for a specific profile (bsi, bsiv11, bsiv20, bsiv21, ntia, fsct, interlynk). 'bsi' is an alias for bsiv21.")
}

// resolveSections returns the ProfileSections to display.
// When profile is empty, all sections are returned.
// When profile is set, only the matching section is returned.
func resolveSections(profile string) ([]ProfileSection, error) {
	if profile == "" {
		return ProfileSections, nil
	}

	if _, ok := supportedProfiles[profile]; !ok {
		return nil, fmt.Errorf(
			"profile %q is not supported. Supported profiles: bsi (=bsiv21), bsiv11, bsiv20, bsiv21, fsct, ntia, interlynk",
			profile,
		)
	}

	sectionName := profileSectionName[profile]
	for _, s := range ProfileSections {
		if s.Name == sectionName {
			return []ProfileSection{s}, nil
		}
	}

	// Should never happen if profileSectionName and ProfileSections are in sync.
	return nil, fmt.Errorf("internal: no section found for profile %q", profile)
}

func printFeaturesHuman(sections []ProfileSection, profile string) {
	total := 0
	for _, s := range sections {
		total += len(s.Features)
	}

	if profile != "" {
		fmt.Printf("Features for profile %q (%d features):\n\n", profile, total)
	} else {
		fmt.Printf("Supported Features (%d total across %d sections):\n\n", total, len(sections))
	}

	for _, section := range sections {
		fmt.Printf("%s:\n", section.Name)
		for _, f := range section.Features {
			fmt.Printf("  - %-35s %s\n", f.Name, f.Description)
		}
		fmt.Println()
	}
}

func printFeaturesJSON(sections []ProfileSection) error {
	type jsonSection struct {
		Name     string           `json:"name"`
		Features []ProfileFeature `json:"features"`
	}

	out := make([]jsonSection, 0, len(sections))
	for _, s := range sections {
		out = append(out, jsonSection{
			Name:     s.Name,
			Features: s.Features,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(map[string]interface{}{
		"sections": out,
	})
}
