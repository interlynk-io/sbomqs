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

	fmt.Fprintf(os.Stdout, "\n\033[36m \t\t\t\t BASIC POLICY REPORT\033[36m\n")
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

	// Defensive copy + deterministic ordering by policy name
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	fmt.Fprintf(os.Stdout, "\n\033[1m \t\t--- TABLE DETAILED POLICY REPORT ---\033[0m\n")

	// Per-policy tables
	for _, res := range sorted {
		// Policy header
		fmt.Fprintf(os.Stdout, "\n\033[1mPolicy: %s (action=%s, result=%s, checked=%d, violations=%d)\033[0m\n",
			res.Name, res.Action, res.Result, res.TotalChecked, res.ViolationCnt)

		// Prepare table writer per policy
		tw := tablewriter.NewWriter(os.Stdout)
		tw.SetAutoWrapText(false)
		tw.SetBorder(true)
		tw.SetRowLine(false)

		tw.SetHeader([]string{"COMPONENT", "FIELD", "ACTUAL", "REASON"})

		// Build rows: default behaviour is to show failures only.
		type row struct {
			component string
			field     string
			actual    string
			outcome   string
			reason    string
		}
		rows := []row{}

		// Prefer modern `PolicyResults` if present
		if len(res.PolicyResults) > 0 {
			for _, pr := range res.PolicyResults {
				// show only failures by default
				if pr.Outcome == "pass" {
					continue
				}
				actual := ""
				if len(pr.Actual) > 0 {
					actual = strings.Join(pr.Actual, ", ")
				}
				rows = append(rows, row{
					component: pr.ComponentName,
					field:     pr.Field,
					actual:    actual,
					outcome:   pr.Outcome,
					reason:    pr.Reason,
				})
			}
		}

		// If no failure rows to print:
		// - But we have PolicyResults (means all checks passed) -> print pass rows
		// - Else -> print "No violations"
		if len(rows) == 0 {
			if len(res.PolicyResults) > 0 {
				// populate rows with passing checks so we show non-violations
				for _, pr := range res.PolicyResults {
					// include passes; if some fails existed they'd already be in rows above
					actual := ""
					if len(pr.Actual) > 0 {
						actual = strings.Join(pr.Actual, ", ")
					}
					// For clarity put reason empty for passes
					rows = append(rows, row{
						component: pr.ComponentName,
						field:     pr.Field,
						actual:    actual,
						outcome:   pr.Outcome,
						reason:    pr.Reason,
					})
				}
			} else {
				// truly no records at all (no PolicyResults and no Violations)
				tw.Append([]string{"", "", "", "No violations"})
				tw.Render()
				continue
			}
		}

		// Sort rows deterministically: by component name, then field
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].component == rows[j].component {
				return rows[i].field < rows[j].field
			}
			return rows[i].component < rows[j].component
		})

		// Append to table writer
		for _, rr := range rows {
			// We only render COMPONENT, FIELD, ACTUAL, REASON columns (no outcome column here).
			// If needed in the future, we can switch to a verbose mode that shows outcome too.
			tw.Append([]string{rr.component, rr.field, rr.actual, rr.reason})
		}
		tw.Render()
	}

	fmt.Fprintf(os.Stdout, "\n\033[1m\033[32m \t\t--- SUMMARY TABLE ---\033[1m\n")

	sum := tablewriter.NewWriter(os.Stdout)
	sum.SetHeader([]string{"POLICY", "RESULT", "CHECKED", "VIOLATIONS"})
	for _, r := range sorted {
		sum.Append([]string{
			r.Name,
			r.Result,
			fmt.Sprintf("%d", r.TotalChecked),
			fmt.Sprintf("%d", r.ViolationCnt),
		})
	}
	sum.Render()

	return nil
}
