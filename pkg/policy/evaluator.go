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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// EvalPolicy evaluates a single policy against a document using an extractor.
func EvalPolicy(ctx context.Context, p Policy, doc sbom.Document, fieldExtractor interface{}) (Result, error) {
	// TODO: implement evaluation logic

	result := NewResult(p)
	result.GeneratedAt = time.Now().UTC()

	components := doc.Components()
	result.TotalChecked = len(components)

	violations := []Violation{}

	// evaluate per component
	for _, comp := range components {
		fmt.Println("comp: ", comp)
		for _, rule := range p.Rules {
			values := fieldExtractor.Values(comp, rule.Field)

			if p.Type == "required" {
				ok := fieldExtractor.HasField(comp, rule.Field)
				if !ok {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         rule.Field,
						Actual:        rule.Values,
						Reason:        "missing field",
					})
				}

			}

			matched := anyMatch(values, rule.Values, rule.Patterns)
			if p.Type == "whitelist" {
				if !matched {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         rule.Field,
						Actual:        rule.Values,
						Reason:        "value not in whitelist",
					})
				}
			} else if p.Type == "blacklist" {
				if matched {
					violations = append(violations, Violation{
						ComponentName: comp.GetName(),
						Field:         rule.Field,
						Actual:        rule.Values,
						Reason:        "value in blacklist",
					})
				}
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

// anyMatch checks exact value matches or regex matches
func anyMatch(values []string, allowed []string, patterns []*regexp.Regexp) bool {
	if len(values) == 0 {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	for _, v := range values {
		if _, ok := allowedSet[v]; ok {
			return true
		}
	}
	for _, re := range patterns {
		for _, v := range values {
			if re.MatchString(v) {
				return true
			}
		}
	}
	return false
}
