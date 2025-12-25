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
	"regexp"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"go.uber.org/zap"
)

// EvaluatePolicyAgainstSBOMs evaluates a single policy against a SBOMs.
func EvaluatePolicyAgainstSBOMs(ctx context.Context, policy Policy, doc sbom.Document, fieldExtractor *Extractor) (PolicyResult, error) {
	log := logger.FromContext(ctx)

	log.Info("Starting policy evaluation",
		zap.String("policy", policy.Name),
		zap.String("type", policy.Type),
	)

	policyResult := NewPolicyResult(policy)

	components := doc.Components()
	policyResult.TotalComponents = len(components)

	log.Debug("Policy evaluation context prepared",
		zap.Int("components", len(components)),
	)

	// compile regex present in pattern rules
	compiledRules, err := compilePatternRules(policy)
	if err != nil {
		log.Error("Failed to compile policy rules",
			zap.String("policy", policy.Name),
			zap.Error(err),
		)
		return PolicyResult{}, err
	}

	log.Debug("Policy rules compiled",
		zap.Int("rules", len(compiledRules)),
	)

	totalChecks := 0
	policyResults := make([]RuleResult, 0, len(components)*len(compiledRules))

	// evaluate components against list of all rules in a single policy
	for _, comp := range components {
		var compID, compName string
		if comp != nil {
			compID = comp.GetID()
		}
		if comp != nil {
			compName = comp.GetName()
		}

		// evaluate each component against list of all rules
		for _, compileRule := range compiledRules {
			totalChecks++
			// evaluate rule

			declaredRule := compileRule.Rule
			declaredField := declaredRule.Field
			declaredValues := declaredRule.Values
			patterns := compileRule.Patterns

			// retreive the actual values from component for that respective field
			// example: `license`, `supplier`, `checksum`, `author`, etc
			actualValues := fieldExtractor.RetrieveValues(comp, declaredField)

			// default outcome/pass reason
			result := "pass"
			reason := "present"

			// required rule: presence check
			if RULE_TYPE(policy.Type) == REQUIRED {
				ok := fieldExtractor.HasField(comp, declaredField)
				if !ok {
					result = "fail"
					reason = "missing field"
				}

			} else {
				// for whitelist/blacklist do matching
				matched := anyMatch(actualValues, declaredValues, patterns)

				switch RULE_TYPE(policy.Type) {
				case WHITELIST:
					if !matched {
						result = "fail"
						reason = "value not in whitelist"
					}
				case BLACKLIST:
					if matched {
						result = "fail"
						reason = "value in blacklist"
					}
				default:
					// if unknown type, treat as pass (or change to fail depending on your policy)
				}
			}

			pr := RuleResult{
				ComponentID:   compID,
				ComponentName: compName,
				DeclaredField: declaredField,
				ActualValues:  actualValues,
				Result:        result,
				Reason:        reason,
			}

			policyResults = append(policyResults, pr)

		}
	}

	// assign results
	policyResult.RuleResults = policyResults
	policyResult.TotalChecks = totalChecks

	// compute ViolationCnt (failed outcomes)
	violationCount := 0
	for _, pr := range policyResults {
		if pr.Result == "fail" {
			violationCount++
		}
	}
	policyResult.ViolationCnt = violationCount

	// Decide outcome
	if policyResult.ViolationCnt == 0 {
		policyResult.OverallResult = "pass"
	} else {
		switch policy.Action {
		case "warn":
			policyResult.OverallResult = "warn"
		case "pass":
			policyResult.OverallResult = "pass"
		default:
			policyResult.OverallResult = "fail"
		}
	}

	log.Info("Policy evaluation completed",
		zap.String("policy", policy.Name),
		zap.Int("checks", totalChecks),
		zap.Int("violations", violationCount),
		zap.String("result", policyResult.OverallResult),
	)

	return *policyResult, nil
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
