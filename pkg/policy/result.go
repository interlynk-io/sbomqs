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

import "time"

// Result represent the evaluation result of policay against SBOM
type Result struct {
	Name         string      `json:"name,omitempty"`
	Type         string      `json:"type,omitempty"`
	Action       string      `json:"action,omitempty"`
	Result       string      `json:"result"`
	Violations   []Violation `json:"violations,omitempty"`
	TotalChecked int         `json:"total_checked,omitempty"`
	ViolationCnt int         `json:"violation_count,omitempty"`
	GeneratedAt  time.Time   `json:"generated_at,omitempty"`
}

type Violation struct {
	ComponentName string   `json:"component_name"`
	Field         string   `json:"field"`
	Actual        []string `json:"actual,omitempty"`
	Reason        string   `json:"reason"`
}

func NewResult(p Policy) *Result {
	return &Result{
		Name:   p.Name,
		Type:   p.Type,
		Action: p.Action,
	}
}
