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
	"regexp"
)

type RULE_TYPE string

var (
	REQUIRED  RULE_TYPE = "required"
	WHITELIST RULE_TYPE = "whitelist"
	BLACKLIST RULE_TYPE = "blacklist"
)

// Rule represents field/values or field/patterns
type Rule struct {
	Field    string   `yaml:"field"`
	Values   []string `yaml:"values,omitempty"`
	Patterns []string `yaml:"patterns,omitempty"`
}

// Precompile regex patterns per rule (do once)
type compiledRule struct {
	Rule     Rule
	Patterns []*regexp.Regexp
}

// compiles regex present in patterns
func compilePatternRules(policy Policy) ([]compiledRule, error) {
	compiledRules := make([]compiledRule, 0, len(policy.Rules))

	for _, rule := range policy.Rules {
		compileRule := compiledRule{Rule: rule}

		// compile each regex pattern in the rule
		if len(rule.Patterns) > 0 {
			// compile each patterns values
			for _, pattern := range rule.Patterns {
				regexPattern, err := regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("invalid pattern %q in policy %s: %w", pattern, policy.Name, err)
				}
				compileRule.Patterns = append(compileRule.Patterns, regexPattern)
			}
		}
		compiledRules = append(compiledRules, compileRule)
	}

	return compiledRules, nil
}
