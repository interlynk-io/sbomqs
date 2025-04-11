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

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-github/v52/github"
	"github.com/spf13/cobra"
	version "sigs.k8s.io/release-utils/version"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sbomqs",
	Short: "sbomqs application provides sbom quality scores.",
	Long: `SBOM Quality Score (sbomqs) is a standardized metric to
produce a calculated score that represents a level of “quality”
when using an SBOM. The sbomqs is intended to help customers make
an assessment of a SBOM acceptance risk based on their personal risk tolerance.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	checkIfLatestRelease()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func checkIfLatestRelease() {
	if os.Getenv("INTERLYNK_DISABLE_VERSION_CHECK") == "" {
		return
	}

	client := github.NewClient(nil)
	rr, resp, err := client.Repositories.GetLatestRelease(context.Background(), "interlynk-io", "sbomqs")
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		return
	}

	verLatest, err := semver.NewVersion(version.GetVersionInfo().GitVersion)
	if err != nil {
		return
	}

	verInstalled, err := semver.NewVersion(rr.GetTagName())
	if err != nil {
		return
	}

	result := verInstalled.Compare(verLatest)
	if result < 0 {
		fmt.Printf("\nA new version of sbomqs is available %s.\n\n", rr.GetTagName())
	}
}
