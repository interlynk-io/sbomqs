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
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// EvalPolicy evaluates a single policy against a document using an extractor.
func EvalPolicy(ctx context.Context, p Policy, doc sbom.Document, fieldExtractor *Extractor) (Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("processing policy evaluation: %s", p.Name, p.Type)

	result := NewResult(p)
	result.GeneratedAt = time.Now().UTC()

	components := doc.Components()
	result.TotalChecked = len(components)

	compiledRules, err := compileRule(p)
	if err != nil {
		return Result{}, err
	}

	violations := []Violation{}

	// evaluate per component
	for _, comp := range components {
		for _, compileRule := range compiledRules {
			rule := compileRule.Rule
			field := rule.Field
			declaredValues := rule.Values

			actualValues := fieldExtractor.Values(comp, field)

			if p.Type == "required" {
				ok := fieldExtractor.HasField(comp, field)
				if !ok {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         field,
						Actual:        actualValues,
						Reason:        "missing field",
					})
				}

			}

			// for whitelist/blacklist evaluate values + patterns
			matched := anyMatch(actualValues, declaredValues, compileRule.Patterns)

			switch p.Type {
			case "whitelist":
				if !matched {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         field,
						Actual:        actualValues,
						Reason:        "value not in whitelist",
					})
				}
			case "blacklist":
				if matched {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         field,
						Actual:        actualValues,
						Reason:        "value in blacklist",
					})
				}
			default:
				// unknown type
			}
		}
	}

	result.Violations = violations
	result.ViolationCnt = len(violations)

	// Decide outcome
	if len(violations) == 0 {
		result.Outcome = "pass"
	} else {
		switch p.Action {
		case "warn":
			result.Outcome = "warn"
		case "pass":
			result.Outcome = "pass"
		default:
			result.Outcome = "fail"
		}
	}

	return *result, nil
}

// anyMatch returns true if at least one of the actual values
// matches either an allowed literal value or a regex pattern.
//
// - actualValues: values extracted from the SBOM (e.g. component licenses)
// - declaredValues: literal values from the policy rule (exact match only)
// - regexPatterns: compiled regex patterns from the policy rule
func anyMatch(actualValues []string, declaredValues []string, regexPatterns []*regexp.Regexp) bool {
	// No values to check against
	if len(actualValues) == 0 {
		return false
	}

	// Build a set for quick exact-match lookups
	declaredSet := make(map[string]struct{}, len(declaredValues))
	for _, value := range declaredValues {
		declaredSet[value] = struct{}{}
	}

	// 1. Check for exact value matches
	for _, actual := range actualValues {
		if _, exists := declaredSet[actual]; exists {
			return true
		}
	}

	// 2. Check for regex pattern matches
	for _, pattern := range regexPatterns {
		for _, actual := range actualValues {
			if pattern.MatchString(actual) {
				return true
			}
		}
	}

	// 3. Nothing matched
	return false
}

// Precompile regex patterns per rule (do once)
type compiledRule struct {
	Rule     Rule
	Patterns []*regexp.Regexp
}

func compileRule(policy Policy) ([]compiledRule, error) {
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
