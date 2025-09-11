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

package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/stretchr/testify/assert/yaml"
)

type Params struct {
	PolicyFile   string
	PolicyName   string
	PolicyType   string
	PolicyRules  []string
	PolicyAction string

	// SBOM input
	SBOMFile string

	// Output
	OutputFmt string

	// Debug
	debug bool
}

// PolicyFile represents the top-level YAML structure
type PolicyFile struct {
	SchemaVersion int      `yaml:"schemaVersion,omitempty"`
	Policy        []Policy `yaml:"policy"`
}

// Policy represents single policy
type Policy struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Rules  []Rule `yaml:"rules"`
	Action string `yaml:"action,omitempty"`
}

// LoadPoliciesFromFile reads a YAML policy file and unmarshals it into policies.
func LoadPoliciesFromFile(path string) ([]Policy, error) {
	policyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(policyBytes, &pf); err != nil {
		return nil, fmt.Errorf("unmarshal policy yaml: %w", err)
	}

	// basic validation
	for i := range pf.Policy {
		if err := ValidatePolicy(&pf.Policy[i]); err != nil {
			return nil, fmt.Errorf("policy[%d] invalid: %w", i, err)
		}

		// update the values for license field
	}
	return pf.Policy, nil
}

// BuildPolicyFromCLI builds a Policy from CLI flags.
// where each element is ONE full rule string, e.g. "field=license,values=MIT,Apache-2.0".
func BuildPolicyFromCLI(name, ptype, action string, ruleFlags []string) (Policy, error) {
	p := Policy{
		Name:   name,
		Type:   ptype,
		Action: action,
		Rules:  []Rule{},
	}

	if len(ruleFlags) == 0 {
		return p, fmt.Errorf("no rules provided")
	}

	for _, rf := range ruleFlags {

		rule, err := parseRuleString(rf)
		if err != nil {
			// include the raw input in the error for easy debugging
			return Policy{}, fmt.Errorf("parse rule %q: %w", rf, err)
		}

		rule.Field = strings.ToLower(strings.TrimSpace(rule.Field))

		p.Rules = append(p.Rules, rule)
	}

	// Optionally run ValidatePolicy here (your existing function)
	if err := ValidatePolicy(&p); err != nil {
		return Policy{}, fmt.Errorf("policy validation failed: %w", err)
	}

	return p, nil
}

// ValidatePolicy performs basic semantic checks on a policy
func ValidatePolicy(p *Policy) error {
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Type != "whitelist" && p.Type != "blacklist" && p.Type != "required" {
		return fmt.Errorf("invalid policy type: %s", p.Type)
	}
	if p.Action == "" {
		p.Action = "warn"
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy must contain at least one rule")
	}
	for i := range p.Rules {
		if p.Type != "required" {
			if len(p.Rules[i].Values) == 0 && len(p.Rules[i].Patterns) == 0 {
				return fmt.Errorf("rule %d: values or patterns required for type %s", i, p.Type)
			}
		}
		if p.Rules[i].Field == "" {
			return fmt.Errorf("rule %d: field is required", i)
		}
	}
	return nil
}
