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

// Result represent the evaluation result of policay against SBOM
type PolicyResult struct {
	PolicyName      string       `json:"name,omitempty"`
	PolicyType      string       `json:"type,omitempty"`
	PolicyAction    string       `json:"action,omitempty"`
	OverallResult   string       `json:"overall_result"`           // overall: pass|warn|fail
	RuleResults     []RuleResult `json:"policy_results,omitempty"` // both passes & fails
	TotalChecks     int          `json:"total_checks,omitempty"`   // number of total check
	TotalRules      int          `json:"total_rules,omitempty"`
	TotalComponents int          `json:"total_components,omitempty"` // number of components scanned
	ViolationCnt    int          `json:"violation_count,omitempty"`  // number of failed policy_results
}

type RuleResult struct {
	ComponentID    string   `json:"component_id,omitempty"`   // component unique id (or "<document>")
	ComponentName  string   `json:"component_name,omitempty"` // friendly name
	DeclaredField  string   `json:"declared_field"`           // the field evaluated (e.g., license)
	DeclaredValues string   `json:"declared_values"`          // the decalred values
	ActualValues   []string `json:"actual_values,omitempty"`  // actual values seen on SBOM
	Result         string   `json:"result"`                   // "pass" | "fail"
	Reason         string   `json:"reason,omitempty"`         // human-friendly reason for failure
}

func NewPolicyResult(p Policy) *PolicyResult {
	return &PolicyResult{
		PolicyName:   p.Name,
		PolicyType:   p.Type,
		PolicyAction: p.Action,
		TotalRules:   len(p.Rules),
	}
}
