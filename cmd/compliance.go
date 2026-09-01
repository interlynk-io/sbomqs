// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/interlynk-io/sbomqs/v2/pkg/engine"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/spf13/cobra"
)

// complianceCmd represents the compliance command for checking SBOM compliance against various standards.
// Supports NTIA minimum elements, BSI TR-03183-2 (v1.1 and v2.0), FSCT v3, and OpenChain Telco standards.
var complianceCmd = &cobra.Command{
	Use:          "compliance [flags] <sbom_file>",
	SilenceUsage: true,
	Short:        "compliance command checks an SBOM for compliance with SBOM standards",
	Long: `
Check if our SBOM meets compliance requirements for various standards, such as NTIA minimum elements,
BSI TR-03183-2, Framing Software Component Transparency (v3) and OpenChain Telco.
	`,
	Example: ` sbomqs compliance  < --ntia | --ntia-2021 | --bsi | --bsi-v2 | --bsi-v21 | --fsct | --oct >  [--basic | --json]   <SBOM file>

  # Check a NTIA minimum elements (CISA-2026) compliance against a SBOM in a table output
  sbomqs compliance --ntia samples/photon.spdx.json

  # Check a NTIA minimum elements (2021) compliance against a SBOM in a table output
  sbomqs compliance --ntia-2021 samples/photon.spdx.json

  # Check BSI TR-03183-2 compliance (latest version, currently v2.1.0)
  sbomqs compliance --bsi samples/sbom_cdx.json

  # Check a BSI TR-03183-2 v1.1 compliance against a SBOM in a table output
  sbomqs compliance --bsi-v1 samples/photon.spdx.json

  # Check a BSI TR-03183-2 v2.0.0 compliance against a SBOM in a table output
  sbomqs compliance --bsi-v2 samples/photon.spdx.json

  # Check a BSI TR-03183-2 v2.1.0 compliance against a SBOM in a table output
  sbomqs compliance --bsi-v21 samples/sbom_cdx.json

   # Check a Framing Software Component Transparency (v3) compliance against a SBOM in a table output
  sbomqs compliance --fsct samples/photon.spdx.json

  # Check a OpenChain Telco compliance against a SBOM in a JSON output
  sbomqs compliance --oct --json samples/photon.spdx.json

   # Check a Framing Software Component Transparency (v3) compliance against a SBOM in a table colorful output
  sbomqs compliance --fsct --color samples/photon.spdx.json

`,
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			_ = cmd.Help()
			return fmt.Errorf("please provide a path to an SBOM file or directory")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		debug, _ := cmd.Flags().GetBool("debug")

		// Initialize logger once
		logger.Init(debug)
		defer logger.Sync()

		ctx := logger.WithLogger(context.Background())

		engParams := setupEngineParams(cmd, args)
		return engine.ComplianceRun(ctx, engParams)
	},
}

func setupEngineParams(cmd *cobra.Command, args []string) *engine.Params {
	engParams := &engine.Params{}

	engParams.Basic, _ = cmd.Flags().GetBool("basic")
	engParams.Detailed, _ = cmd.Flags().GetBool("detailed")
	engParams.JSON, _ = cmd.Flags().GetBool("json")
	engParams.Color, _ = cmd.Flags().GetBool("color")

	engParams.Ntia, _ = cmd.Flags().GetBool("ntia")
	if v, _ := cmd.Flags().GetBool("ntia-2021"); v {
		engParams.Ntia2021 = true
	}
	if v, _ := cmd.Flags().GetBool("ntia2021"); v {
		engParams.Ntia2021 = true
	}
	engParams.Bsi, _ = cmd.Flags().GetBool("bsi")
	engParams.BsiV1, _ = cmd.Flags().GetBool("bsi-v1")
	if v, _ := cmd.Flags().GetBool("bsi-v1.1"); v {
		engParams.BsiV1 = true
	}
	if v, _ := cmd.Flags().GetBool("bsiv11"); v {
		engParams.BsiV1 = true
	}

	engParams.BsiV2, _ = cmd.Flags().GetBool("bsi-v2")
	if v, _ := cmd.Flags().GetBool("bsi-v2.0"); v {
		engParams.BsiV2 = true
	}
	if v, _ := cmd.Flags().GetBool("bsiv20"); v {
		engParams.BsiV2 = true
	}

	engParams.BsiV21, _ = cmd.Flags().GetBool("bsi-v21")
	if v, _ := cmd.Flags().GetBool("bsi-v2.1"); v {
		engParams.BsiV21 = true
	}
	if v, _ := cmd.Flags().GetBool("bsiv21"); v {
		engParams.BsiV21 = true
	}
	engParams.Oct, _ = cmd.Flags().GetBool("oct")
	if v, _ := cmd.Flags().GetBool("oct-v1.1"); v {
		engParams.Oct = true
	}
	if v, _ := cmd.Flags().GetBool("octv11"); v {
		engParams.Oct = true
	}
	engParams.Fsct, _ = cmd.Flags().GetBool("fsct")
	engParams.Cisa2026, _ = cmd.Flags().GetBool("cisa-2026")
	if v, _ := cmd.Flags().GetBool("cisa2026"); v {
		engParams.Cisa2026 = true
	}
	if v, _ := cmd.Flags().GetBool("cisa"); v {
		engParams.Cisa2026 = true
	}
	engParams.Cisa2021, _ = cmd.Flags().GetBool("cisa-2021")
	if v, _ := cmd.Flags().GetBool("cisa2021"); v {
		engParams.Cisa2021 = true
	}

	engParams.Debug, _ = cmd.Flags().GetBool("debug")

	engParams.SignaturePath, _ = cmd.Flags().GetString("signature")
	engParams.PublicKeyPath, _ = cmd.Flags().GetString("public-key")

	engParams.Path = append(engParams.Path, args[0])
	engParams.Blob = args[0]

	return engParams
}

func init() {
	rootCmd.AddCommand(complianceCmd)

	// Debug control
	complianceCmd.Flags().BoolP("debug", "D", false, "debug logging")

	// Output control
	complianceCmd.Flags().BoolP("json", "j", false, "output in json format")
	complianceCmd.Flags().BoolP("basic", "b", false, "output in basic format")
	complianceCmd.Flags().BoolP("detailed", "d", false, "output in detailed format(default)")
	complianceCmd.Flags().BoolP("color", "l", false, "output in colorful")

	// complianceCmd.Flags().BoolP("pdf", "p", false, "output in pdf format")
	complianceCmd.MarkFlagsMutuallyExclusive("json", "basic", "detailed")

	// Standards control
	complianceCmd.Flags().BoolP("ntia", "n", false, "NTIA minimum elements (CISA 2026)")
	complianceCmd.Flags().BoolP("ntia-2021", "", false, "NTIA minimum elements (2021)")
	complianceCmd.Flags().BoolP("ntia2021", "", false, "NTIA minimum elements (2021)")
	complianceCmd.Flags().BoolP("bsi", "c", false, "BSI TR-03183-2 (latest, currently v2.1.0)")
	complianceCmd.Flags().BoolP("bsi-v1", "", false, "BSI TR-03183-2 (v1.1)")
	complianceCmd.Flags().BoolP("bsi-v1.1", "", false, "BSI TR-03183-2 (v1.1)")
	complianceCmd.Flags().BoolP("bsiv11", "", false, "BSI TR-03183-2 (v1.1)")
	complianceCmd.Flags().BoolP("bsi-v2", "s", false, "BSI TR-03183-2 (v2.0.0)")
	complianceCmd.Flags().BoolP("bsi-v2.0", "", false, "BSI TR-03183-2 (v2.0.0)")
	complianceCmd.Flags().BoolP("bsiv20", "", false, "BSI TR-03183-2 (v2.0.0)")
	complianceCmd.Flags().BoolP("bsi-v21", "w", false, "BSI TR-03183-2 (v2.1.0)")
	complianceCmd.Flags().BoolP("bsi-v2.1", "", false, "BSI TR-03183-2 (v2.1.0)")
	complianceCmd.Flags().BoolP("bsiv21", "", false, "BSI TR-03183-2 (v2.1.0)")
	complianceCmd.Flags().BoolP("oct", "t", false, "OpenChain Telco SBOM (v1.1)")
	complianceCmd.Flags().BoolP("oct-v1.1", "", false, "OpenChain Telco SBOM (v1.1)")
	complianceCmd.Flags().BoolP("octv11", "", false, "OpenChain Telco SBOM (v1.1)")
	complianceCmd.Flags().BoolP("fsct", "f", false, "Framing Software Component Transparency (v3)")
	complianceCmd.Flags().BoolP("cisa-2026", "", false, "NTIA Minimum Elements (2026)")
	complianceCmd.Flags().BoolP("cisa2026", "", false, "NTIA Minimum Elements (2026)")
	complianceCmd.Flags().BoolP("cisa", "", false, "NTIA Minimum Elements (2026)")
	complianceCmd.Flags().BoolP("cisa-2021", "", false, "CISA Minimum Elements (2021); alias for NTIA")
	complianceCmd.Flags().BoolP("cisa2021", "", false, "CISA Minimum Elements (2021); alias for NTIA")

	// Signature verification
	complianceCmd.Flags().StringP("signature", "", "", "path to detached signature file for SPDX SBOMs")
	complianceCmd.Flags().StringP("public-key", "", "", "path to public key file for signature verification")
}
