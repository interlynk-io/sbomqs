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

	return Result{}, nil
}
