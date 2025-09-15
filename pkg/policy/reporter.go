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
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/olekukonko/tablewriter"
)

// ReportJSON writes results as pretty-printed JSON to stdout.
func ReportJSON(ctx context.Context, results []Result) error {
	log := logger.FromContext(ctx)
	log.Debugf("JSON Report...")

	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sorted); err != nil {
		return fmt.Errorf("encode results to json: %w", err)
	}
	return nil
}

// ReportBasic writes results in a human-friendly basic format.
func ReportBasic(ctx context.Context, results []Result) error {
	log := logger.FromContext(ctx)
	log.Debugf("Basic Report....")

	// Sort results by policy name for deterministic output
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	// === Summary Table ===
	summary := tablewriter.NewWriter(os.Stdout)
	summary.SetHeader([]string{"POLICY", "TYPE", "ACTION", "RESULT", "CHECKED", "VIOLATIONS", "GENERATED_AT"})

	for _, r := range sorted {
		summary.Append([]string{
			r.Name,
			r.Type,
			r.Action,
			r.Result,
			fmt.Sprintf("%d", r.TotalChecked),
			fmt.Sprintf("%d", r.ViolationCnt),
			r.GeneratedAt.Format(time.RFC3339),
		})
	}
	summary.Render() // prints the table

	return nil
}

// ReportTable writes results in a per-policy, per-violation detail table format.
func ReportTable(ctx context.Context, results []Result) error {
	log := logger.FromContext(ctx)
	log.Debugf("Table Report...")

	sorted := make([]Result, len(results))
	copy(sorted, results)

	// sort out by policy
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	// total violations across all policies
	totalViolations := 0
	for _, r := range results {
		totalViolations += r.ViolationCnt
	}

	if totalViolations == 0 {
		return noViolationFmt(results)
	}

	// === Detailed Violations ===
	fmt.Fprintln(os.Stdout, "\n--- Detailed Violations Report ---")

	for _, r := range sorted {
		if len(r.Violations) == 0 {
			continue
		}
		fmt.Fprintf(os.Stdout, "\nPolicy: %s (outcome=%s, total components=%d, violations=%d)\n", r.Name, r.Result, r.TotalChecked, len(r.Violations))

		violations := tablewriter.NewWriter(os.Stdout)
		violations.SetHeader([]string{"COMPONENT", "FIELD", "ACTUAL", "REASON"})

		// sort violations
		vcopy := make([]Violation, len(r.Violations))
		copy(vcopy, r.Violations)
		sort.Slice(vcopy, func(i, j int) bool {
			if vcopy[i].ComponentName == vcopy[j].ComponentName {
				return vcopy[i].Field < vcopy[j].Field
			}
			return vcopy[i].ComponentName < vcopy[j].ComponentName
		})

		for _, v := range vcopy {
			actual := ""
			if len(v.Actual) > 0 {
				actual = strings.Join(v.Actual, ", ")
			}
			violations.Append([]string{v.ComponentName, v.Field, actual, v.Reason})
		}

		violations.Render()
	}
	return nil
}

// when no violations at all, print a concise friendly message and return.
func noViolationFmt(results []Result) error {
	fmt.Fprintln(os.Stdout, "\nNo violations found — all policies passed.")
	fmt.Fprintf(os.Stdout, "Policies evaluated: %d\n", len(results))

	for _, result := range results {
		fmt.Fprintf(os.Stdout, " - policy=%s, \toutcome=%s, \tchecked=%d\n", result.Name, result.Result, result.TotalChecked)
	}

	return nil
}
