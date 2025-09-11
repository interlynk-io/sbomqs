// Copyright 2025 Interlynk.io
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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/policy"
	"github.com/spf13/cobra"
)

// policyCmdConfig holds configuration parsed from CLI flags for the apply command
type policyCmdConfig struct {
	// Policy input
	policyFile   string
	policyName   string
	policyType   string
	policyRules  []string
	policyAction string

	// SBOM input
	inputPath string

	// Output
	outputFmt string

	// Debug
	debug bool
}

// applyCmd represents the sbomqs apply command
var policyCmd = &cobra.Command{
	Use:          "policy",
	Short:        "Apply SBOM policies to an SBOM document",
	SilenceUsage: true,
	Example: `  sbomqs policy -f policies.yaml samples/sbom.json

  # Inline rule example
  sbomqs policy \
    --name approved_licenses \
    --type whitelist \
    --rules "field=license,values=MIT,Apache-2.0" \
    --action fail \
	samples/sbom.cdx.json
`,
	Args: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("requires a path to an SBOM file or directory of SBOM files")
		}
		if len(args) > 1 {
			return fmt.Errorf("only one file path is allowed, got %d: %v", len(args), args)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Setup logger
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			logger.InitDebugLogger()
		} else {
			logger.InitProdLogger()
		}

		ctx := logger.WithLogger(context.Background())

		cfg := parsePolicyParams(cmd)
		if err := validatePolicyParams(cfg); err != nil {
			return err
		}

		cfg.inputPath = args[0]

		log := logger.FromContext(ctx)
		log.Debugf("Parsed Policy command: %+v", cfg)

		// Load policies
		var policies []policy.Policy
		var err error

		if cfg.policyFile != "" {
			log.Debugf("loading policy from file")

			policies, err = policy.LoadPoliciesFromFile(cfg.policyFile)
			if err != nil {
				return fmt.Errorf("failed to load policy file %s: %w", cfg.policyFile, err)
			}
		} else {
			logger.FromContext(ctx).Debugf("loading policy from inline commands")

			p, err := policy.BuildPolicyFromCLI(cfg.policyName, cfg.policyType, cfg.policyAction, cfg.policyRules)
			if err != nil {
				return fmt.Errorf("failed to build policy from CLI: %w", err)
			}
			policies = []policy.Policy{p}
		}

		policyConfig := convertPolicyCmdToEngineParams(cfg)
		log.Debugf("policies: %s", policies)

		// proceed with policy engine
		if err := policy.Engine(ctx, policyConfig, policies); err != nil {
			return fmt.Errorf("policy engine failed: %w", err)
		}

		return nil
	},
}

func parsePolicyParams(cmd *cobra.Command) *policyCmdConfig {
	cfg := &policyCmdConfig{}

	// extract policy file
	cfg.policyFile, _ = cmd.Flags().GetString("file")

	// extract policy name
	cfg.policyName, _ = cmd.Flags().GetString("name")

	// extract policy type
	cfg.policyType, _ = cmd.Flags().GetString("type")

	// extract policy rules
	ruleFlags, _ := cmd.Flags().GetStringArray("rules")

	cfg.policyRules = ruleFlags

	// // extract policy action
	cfg.policyAction, _ = cmd.Flags().GetString("action")

	// // extract o/p
	cfg.outputFmt, _ = cmd.Flags().GetString("output")
	cfg.debug, _ = cmd.Flags().GetBool("debug")

	return cfg
}

func convertPolicyCmdToEngineParams(uCmd *policyCmdConfig) *policy.Params {
	return &policy.Params{
		PolicyFile:   uCmd.policyFile,
		PolicyName:   uCmd.policyName,
		PolicyType:   uCmd.policyType,
		PolicyRules:  uCmd.policyRules,
		PolicyAction: uCmd.policyAction,
		OutputFmt:    uCmd.outputFmt,
		SBOMFile:     uCmd.inputPath,
	}
}

func init() {
	rootCmd.AddCommand(policyCmd)

	policyCmd.Flags().StringP("file", "f", "", "policy file (yaml)")
	policyCmd.Flags().String("name", "", "policy name (when using CLI inline rules)")
	policyCmd.Flags().String("type", "", "policy type: whitelist|blacklist|required")
	policyCmd.Flags().StringArrayP("rules", "r", nil, "Rule (repeatable): field=...,values=v1,v2")
	policyCmd.Flags().String("action", "warn", "policy action on violation: fail|warn|pass")
	policyCmd.Flags().StringP("output", "o", "basic", "output format: table|json|basic")
	policyCmd.Flags().BoolP("debug", "D", false, "Enable debug logging")
}

func validatePolicyParams(cfg *policyCmdConfig) error {
	// either provide policy file or inline policy via commands
	if cfg.policyFile != "" && cfg.policyName != "" {
		return errors.New("specify either --file or inline policy flags, not both")
	}

	// inline policy requires name, type, rules, action
	if cfg.policyFile == "" {
		if cfg.policyName == "" {
			return errors.New("policy name (--name) is required when using inline policy flags")
		}
		if cfg.policyType == "" {
			return errors.New("policy type (--type) is required when using inline policy flags")
		}
		if len(cfg.policyRules) == 0 {
			return errors.New("at least one --rule is required when using inline policy flags")
		}

		if cfg.policyAction == "" {
			return errors.New("policy action (--action) is required when using inline policy flags")
		}
	}

	// Validate output format
	o := strings.ToLower(cfg.outputFmt)
	if o != "table" && o != "json" && o != "basic" {
		return fmt.Errorf("unsupported output format: %s", cfg.outputFmt)
	}

	return nil
}
