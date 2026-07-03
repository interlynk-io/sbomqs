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

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/olekukonko/tablewriter"
	"go.uber.org/zap"
)

// ReportJSON writes results as pretty-printed JSON to stdout.
func ReportJSON(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Info("Generating JSON policy report",
		zap.Int("policies", len(results)),
	)

	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sorted); err != nil {
		return fmt.Errorf("encode results to json: %w", err)
	}

	log.Info("JSON policy report written")
	return nil
}

// centerTitle centers a title string within a given width
func centerTitle(title string, width int) string {
	if width <= 0 || len(title) >= width {
		return title
	}
	leftPad := (width - len(title)) / 2
	return fmt.Sprintf("%s%s", strings.Repeat(" ", leftPad), title)
}

// ReportBasic writes results in a human-friendly basic format.
func ReportBasic(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Info("Generating basic policy report",
		zap.Int("policies", len(results)),
	)

	// Sort results by policy name for deterministic output
	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	// Render table to buffer first to calculate width
	var buf strings.Builder
	summary := tablewriter.NewWriter(&buf)
	summary.SetHeader([]string{"POLICY", "TYPE", "ACTION", "RESULT", "LEVEL", "COMPONENTS", "VIOLATIONS", "RULES APPLIED"})

	for _, r := range sorted {
		// Show "-" for document-level policies in COMPONENTS column
		componentsDisplay := fmt.Sprintf("%d", r.TotalComponents)
		if r.Level == "doc" {
			componentsDisplay = "-"
		}
		summary.Append([]string{
			r.PolicyName,
			r.PolicyType,
			r.PolicyAction,
			r.OverallResult,
			r.Level,
			componentsDisplay,
			fmt.Sprintf("%d", r.ViolationCnt),
			fmt.Sprintf("%d", r.TotalRules),
		})
	}
	summary.Render()

	// Calculate table width from rendered output
	tableOutput := buf.String()
	lines := strings.Split(tableOutput, "\n")
	maxWidth := 0
	for _, line := range lines {
		if len(line) > maxWidth {
			maxWidth = len(line)
		}
	}

	// Print centered title
	title := "BASIC POLICY REPORT"
	centeredTitle := centerTitle(title, maxWidth)
	_, _ = fmt.Fprintf(os.Stdout, "\n\033[36m%s\033[0m\n", centeredTitle)

	// Print the table
	_, _ = fmt.Fprint(os.Stdout, tableOutput)

	log.Info("Basic policy report written")
	return nil
}

// ReportTable writes results in a per-policy, per-violation detail table format.
func ReportTable(ctx context.Context, results []PolicyResult) error {
	log := logger.FromContext(ctx)
	log.Info("Generating Table policy report",
		zap.Int("policies", len(results)),
	)

	// Defensive copy + deterministic ordering by policy name
	sorted := make([]PolicyResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyName < sorted[j].PolicyName })

	// First pass: determine max width of per-policy detail tables
	var detailTablesBuf strings.Builder
	maxDetailWidth := 0

	for _, res := range sorted {
		// Prepare table writer per policy
		maxColWidth := 36
		tw := tablewriter.NewWriter(&detailTablesBuf)
		tw.SetAutoWrapText(true)
		tw.SetReflowDuringAutoWrap(true)
		tw.SetColWidth(maxColWidth)
		tw.SetBorder(true)
		tw.SetRowLine(false)
		tw.SetHeader([]string{"COMPONENT", "FIELD", "ACTUAL", "REASON"})

		// Build rows
		type row struct {
			component string
			field     string
			actual    string
			result    string
			reason    string
		}
		rows := []row{}

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

		if len(rows) == 0 {
			if len(res.RuleResults) > 0 {
				for _, pr := range res.RuleResults {
					actual := ""
					if len(pr.ActualValues) > 0 {
						actual = strings.Join(pr.ActualValues, ", ")
					}
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

		sort.Slice(rows, func(i, j int) bool {
			if rows[i].component == rows[j].component {
				return rows[i].field < rows[j].field
			}
			return rows[i].component < rows[j].component
		})

		for _, rr := range rows {
			componentWrapped, actualWrapped := wrapLongCells(rr.component, rr.actual, maxColWidth)
			tw.Append([]string{componentWrapped, rr.field, actualWrapped, rr.reason})
		}
		tw.Render()

		// Check width after each table
		lines := strings.Split(detailTablesBuf.String(), "\n")
		for _, line := range lines {
			if len(line) > maxDetailWidth {
				maxDetailWidth = len(line)
			}
		}
		detailTablesBuf.Reset()
	}

	// Calculate summary table width separately
	var summaryBuf strings.Builder
	sum := tablewriter.NewWriter(&summaryBuf)
	sum.SetHeader([]string{"POLICY", "RESULT", "COMPONENTS", "VIOLATIONS", "RULES APPLIED"})
	for _, r := range sorted {
		sum.Append([]string{
			r.PolicyName,
			r.OverallResult,
			fmt.Sprintf("%d", r.TotalComponents),
			fmt.Sprintf("%d", r.ViolationCnt),
			fmt.Sprintf("%d", r.TotalRules),
		})
	}
	sum.Render()

	summaryLines := strings.Split(summaryBuf.String(), "\n")
	maxSummaryWidth := 0
	for _, line := range summaryLines {
		if len(line) > maxSummaryWidth {
			maxSummaryWidth = len(line)
		}
	}

	// Print centered main title over detail tables
	mainTitle := "DETAILED POLICY REPORT"
	centeredMainTitle := centerTitle(mainTitle, maxDetailWidth)
	_, _ = fmt.Fprintf(os.Stdout, "\n\033[1m%s\033[0m\n", centeredMainTitle)

	// Print all policy tables (actual output)
	for _, res := range sorted {
		// Policy header (bold)
		_, _ = fmt.Fprintf(os.Stdout, "\n\033[1mPolicy: %s (result=%s, violations=%d, total_checks=%d, components=%d, total_rules_applied=%d)\033[0m\n",
			res.PolicyName, res.OverallResult, res.ViolationCnt, res.TotalChecks, res.TotalComponents, res.TotalRules)

		// Render individual policy table
		maxColWidth := 36
		tw := tablewriter.NewWriter(os.Stdout)
		tw.SetAutoWrapText(true)
		tw.SetReflowDuringAutoWrap(true)
		tw.SetColWidth(maxColWidth)
		tw.SetBorder(true)
		tw.SetRowLine(false)
		tw.SetHeader([]string{"COMPONENT", "FIELD", "ACTUAL", "REASON"})

		type row struct {
			component string
			field     string
			actual    string
			result    string
			reason    string
		}
		rows := []row{}

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

		if len(rows) == 0 {
			if len(res.RuleResults) > 0 {
				for _, pr := range res.RuleResults {
					actual := ""
					if len(pr.ActualValues) > 0 {
						actual = strings.Join(pr.ActualValues, ", ")
					}
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

		sort.Slice(rows, func(i, j int) bool {
			if rows[i].component == rows[j].component {
				return rows[i].field < rows[j].field
			}
			return rows[i].component < rows[j].component
		})

		for _, rr := range rows {
			componentWrapped, actualWrapped := wrapLongCells(rr.component, rr.actual, maxColWidth)
			tw.Append([]string{componentWrapped, rr.field, actualWrapped, rr.reason})
		}
		tw.Render()
	}

	// Print centered summary title (green and bold) over summary table
	summaryTitle := "--- SUMMARY TABLE ---"
	centeredSummaryTitle := centerTitle(summaryTitle, maxSummaryWidth)
	_, _ = fmt.Fprintf(os.Stdout, "\n\033[1m\033[32m%s\033[0m\n", centeredSummaryTitle)

	// Render summary table
	sum = tablewriter.NewWriter(os.Stdout)
	sum.SetHeader([]string{"POLICY", "RESULT", "LEVEL", "COMPONENTS", "VIOLATIONS", "RULES APPLIED"})
	for _, r := range sorted {
		// Show "-" for document-level policies in COMPONENTS column
		componentsDisplay := fmt.Sprintf("%d", r.TotalComponents)
		if r.Level == "doc" {
			componentsDisplay = "-"
		}
		sum.Append([]string{
			r.PolicyName,
			r.OverallResult,
			r.Level,
			componentsDisplay,
			fmt.Sprintf("%d", r.ViolationCnt),
			fmt.Sprintf("%d", r.TotalRules),
		})
	}
	sum.Render()

	log.Info("Table policy report written")
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
