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

package list

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

type OptionList func(r *Report)

func NewListReport(ctx context.Context, results []*Result, opts ...OptionList) *Report {
	r := &Report{
		Ctx:     ctx,
		Results: results,
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func WithFormat(c string) OptionList {
	return func(r *Report) {
		r.Format = c
	}
}

func WithColor(c bool) OptionList {
	return func(r *Report) {
		r.Color = c
	}
}

func WithValues(s bool) OptionList {
	return func(r *Report) {
		r.Show = s
	}
}

// listReport holds the state for reporting the list command results
type Report struct {
	Ctx     context.Context
	Results []*Result
	Format  string
	Color   bool
	Show    bool // show values for corresponding features
}

// Report renders the list command results in the specified format
func (r *Report) Report() {
	if r.Format == "basic" {
		r.basicReport()
	} else if r.Format == "detailed" {
		r.detailedReport()
	} else if r.Format == "json" {
		r.jsonReport()
	} else {
		r.detailedReport()
	}
}

// basicReport renders the list command results in basic format
func (r *Report) basicReport() {
	for _, result := range r.Results {
		presence := "present"
		if result.Missing {
			presence = "missing"
		}
		if strings.HasPrefix(result.Feature, "comp_") {
			fmt.Printf("\n%s: %s (%s): %d/%d components\n", result.FilePath, result.Feature, presence, len(result.Components), result.TotalComponents)
		} else {
			fmt.Printf("\n%s: %s (%s): %s\n", result.FilePath, result.Feature, presence, result.DocumentProperty.Value)
		}
	}
}

// detailedReport renders the list command results in detailed (table) format
func (r *Report) detailedReport() {
	for _, result := range r.Results {
		presence := "present"
		if result.Missing {
			presence = "missing"
		}
		show := r.Show
		fmt.Println()
		fmt.Printf("File: %s\tFeature: %s (%s)\n", result.FilePath, result.Feature, presence)

		// Initialize tablewriter
		table := tablewriter.NewWriter(os.Stdout)
		if strings.HasPrefix(result.Feature, "comp_") {

			if show {
				table.SetHeader([]string{"Feature", "Component Name", "Version", "Value"})
			} else {
				table.SetHeader([]string{"Feature", "Component Name", "Version"})
			}

			// Component-based feature
			featureCol := fmt.Sprintf("%s (%d/%d)", result.Feature, len(result.Components), result.TotalComponents)
			if len(result.Components) == 0 {
				// No components to display
				fmt.Println(" No components found")
				fmt.Println()
				continue
			}
			// List components
			for _, comp := range result.Components {
				if r.Color {
					featureCol1 := color.New(color.FgHiMagenta).Sprint(featureCol)
					nameCol := color.New(color.FgHiCyan).Sprint(comp.Name)
					versionCol := color.New(color.FgHiGreen).Sprint(comp.Version)
					table.Append([]string{featureCol1, nameCol, versionCol})
				}
				if show {
					table.Append([]string{featureCol, comp.Name, comp.Version, comp.Values})
				} else {
					table.Append([]string{featureCol, comp.Name, comp.Version})
				}
			}

		} else {
			// SBOM-based feature
			featureCol := fmt.Sprintf("%s (%s)", result.Feature, presence)
			table.SetHeader([]string{"Feature", "SBOM Feature", "Value"})

			if r.Color {
				featureCol1 := color.New(color.FgHiCyan).Sprint(featureCol)
				propertyCol := color.New(color.FgHiBlue).Sprint(result.DocumentProperty.Key)
				valueCol := color.New(color.FgHiBlue).Sprint(result.DocumentProperty.Value)
				table.Append([]string{featureCol1, propertyCol, valueCol})
			} else {
				if result.DocumentProperty.Present {
					if result.DocumentProperty.Value == "" {
						result.DocumentProperty.Value = "N/A"
					}
					table.Append([]string{featureCol, result.DocumentProperty.Key, result.DocumentProperty.Value})
				} else {
					if result.DocumentProperty.Value == "" {
						result.DocumentProperty.Value = "N/A"
					}
					table.Append([]string{featureCol, result.DocumentProperty.Key, result.DocumentProperty.Value})
				}
			}
		}

		table.SetRowLine(true)
		table.SetColWidth(50)
		table.SetAutoMergeCellsByColumnIndex([]int{0})
		table.Render()
		fmt.Println()
	}
}

type component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type documentProperty struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Present bool   `json:"present"`
}
type file struct {
	Name             string           `json:"file_name"`
	Feature          string           `json:"feature"`
	Missing          bool             `json:"missing"`
	TotalComponents  int              `json:"total_components,omitempty"`
	Components       []component      `json:"components,omitempty"`
	DocumentProperty documentProperty `json:"document_property,omitempty"`
	Errors           []string         `json:"errors"`
}
type creation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
}
type jsonReport struct {
	RunID        string   `json:"run_id"`
	TimeStamp    string   `json:"timestamp"`
	CreationInfo creation `json:"creation_info"`
	Files        []file   `json:"files"`
}

func newJSONReport() *jsonReport {
	return &jsonReport{
		RunID:     uuid.New().String(),
		TimeStamp: time.Now().UTC().Format(time.RFC3339),
		CreationInfo: creation{
			Name:    "sbomqs",
			Version: version.GetVersionInfo().GitVersion,
			Vendor:  "Interlynk (support@interlynk.io)",
		},
		Files: []file{},
	}
}

// jsonReport renders the list command results in JSON format
func (r *Report) jsonReport() {
	jr := newJSONReport()
	for _, result := range r.Results {
		f := file{
			Name:    result.FilePath,
			Feature: result.Feature,
			Missing: result.Missing,
			Errors:  result.Errors,
		}

		if strings.HasPrefix(result.Feature, "comp_") {
			// Component-based feature
			f.TotalComponents = result.TotalComponents
			for _, comp := range result.Components {
				f.Components = append(f.Components, component{
					Name:    comp.Name,
					Version: comp.Version,
				})
			}
		} else {
			// SBOM-based feature
			f.DocumentProperty = documentProperty{
				Key:     result.DocumentProperty.Key,
				Value:   result.DocumentProperty.Value,
				Present: result.DocumentProperty.Present,
			}
		}

		jr.Files = append(jr.Files, f)
	}

	o, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		fmt.Printf("Failed to print JSON report: %v\n", err)
		return
	}
	fmt.Println(string(o))
}
