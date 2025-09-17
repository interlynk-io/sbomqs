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
	"unicode/utf8"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/olekukonko/tablewriter"
)

// ReportJSON writes results as pretty-printed JSON to stdout.
func ReportJSON(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Debugf("JSON Report...")

	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sorted); err != nil {
		return fmt.Errorf("encode results to json: %w", err)
	}
	return nil
}

// ReportBasic writes results in a human-friendly basic format.
func ReportBasic(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Debugf("Basic Report....")

	// Sort results by policy name for deterministic output
	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	fmt.Fprintf(os.Stdout, "\n\033[36m \t\t\t BASIC POLICY REPORT\033[36m\n")
	// === Summary Table ===
	summary := tablewriter.NewWriter(os.Stdout)
	summary.SetHeader([]string{"POLICY", "TYPE", "ACTION", "RESULT", "COMPONENTS", "VIOLATIONS"})

	for _, r := range sorted {
		summary.Append([]string{
			r.PolicyName,
			r.PolicyType,
			r.PolicyAction,
			r.OverallResult,
			fmt.Sprintf("%d", r.TotalComponents),
			fmt.Sprintf("%d", r.ViolationCnt),
		})
	}
	summary.Render() // prints the table

	return nil
}

// ReportTable writes results in a per-policy, per-violation detail table format.
func ReportTable(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Debugf("Table Report...")

	// Defensive copy + deterministic ordering by policy name
	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	fmt.Fprintf(os.Stdout, "\n\033[1m \t\t=== DETAILED POLICY REPORT ===\033[0m\n")

	// Per-policy tables
	for _, res := range sorted {
		// Policy header
		fmt.Fprintf(os.Stdout, "\n\033[1mPolicy: %s (result=%s, violations=%d, total_checks=%d, components=%d, total_rules_applied=%d)\033[0m\n",
			res.PolicyName, res.OverallResult, res.ViolationCnt, res.TotalChecks, res.TotalComponents, res.TotalRules)

		// Prepare table writer per policy
		maxColWidth := 36
		tw := tablewriter.NewWriter(os.Stdout)
		tw.SetAutoWrapText(true)
		tw.SetReflowDuringAutoWrap(true)
		tw.SetColWidth(maxColWidth)
		tw.SetBorder(true)
		tw.SetRowLine(false)

		tw.SetHeader([]string{"COMPONENT", "FIELD", "ACTUAL", "REASON"})

		// Build rows: default behaviour is to show failures only.
		type row struct {
			component string
			field     string
			actual    string
			result    string
			reason    string
		}
		rows := []row{}

		// Prefer modern `PolicyResults` if present
		if len(res.RuleResults) > 0 {
			for _, pr := range res.RuleResults {
				actual := ""
				if len(pr.ActualValues) > 0 {
					actual = strings.Join(pr.ActualValues, ", ")
				} else {
					actual = "-"
				}
				rows = append(rows, row{
					component: pr.ComponentName,
					field:     pr.DeclaredField,
					actual:    actual,
					result:    pr.Result,
					reason:    pr.Reason,
				})
			}
		}

		// If no failure rows to print:
		// - But we have PolicyResults (means all checks passed) -> print pass rows
		// - Else -> print "No violations"
		if len(rows) == 0 {
			if len(res.RuleResults) > 0 {
				// populate rows with passing checks so we show non-violations
				for _, pr := range res.RuleResults {
					// include passes; if some fails existed they'd already be in rows above
					actual := ""
					if len(pr.ActualValues) > 0 {
						actual = strings.Join(pr.ActualValues, ", ")
					}
					// For clarity put reason empty for passes
					rows = append(rows, row{
						component: pr.ComponentName,
						field:     pr.DeclaredField,
						actual:    actual,
						result:    pr.Reason,
						reason:    pr.Reason,
					})
				}
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
			// warp long column values into multiple lines
			componentWrapped, actualWrapped := wrapLongCells(rr.component, rr.actual, maxColWidth)
			tw.Append([]string{componentWrapped, rr.field, actualWrapped, rr.reason})
		}
		tw.Render()
	}

	fmt.Fprintf(os.Stdout, "\n\033[1m\033[32m \t\t--- SUMMARY TABLE ---\033[1m\n")

	sum := tablewriter.NewWriter(os.Stdout)
	sum.SetHeader([]string{"POLICY", "RESULT", "COMPONENTS", "VIOLATIONS"})
	for _, r := range sorted {
		sum.Append([]string{
			r.PolicyName,
			r.OverallResult,
			fmt.Sprintf("%d", r.TotalComponents),
			fmt.Sprintf("%d", r.ViolationCnt),
		})
	}
	sum.Render()

	return nil
}

// wrapLongCells mutates component and actual strings so long single-token values
// are broken into pieces. Choose width according to your column width.
func wrapLongCells(componentNameValue, actualValue string, width int) (string, string) {
	cmp := componentNameValue
	if utf8.RuneCountInString(cmp) > width {
		cmp = splitEveryN(cmp, width)
	}

	act := actualValue
	if act != "" && utf8.RuneCountInString(act) > width {
		// split on commas/spaces to preserve readability
		sep := ", "
		parts := strings.Split(act, sep)
		for i, part := range parts {
			if utf8.RuneCountInString(part) > width {
				parts[i] = splitEveryN(part, width)
			}
		}
		act = strings.Join(parts, sep)
		// fallback: if still too long, hard-split
		if utf8.RuneCountInString(act) > width {
			act = splitEveryN(act, width)
		}
	}
	return cmp, act
}

// splitEveryN inserts '\n' every n runes into s.
// It preserves existing newlines and whitespace.
func splitEveryN(s string, n int) string {
	if n <= 0 {
		return s
	}
	if s == "" {
		return s
	}

	// Fast path: if already contains whitespace and is shorter than n, keep it
	if utf8.RuneCountInString(s) <= n {
		return s
	}

	var b strings.Builder
	count := 0
	for _, r := range s {
		b.WriteRune(r)
		count++
		if count >= n {
			b.WriteRune('\n')
			count = 0
		}
	}
	return b.String()
}
