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

package formulae

import (
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/stretchr/testify/assert"
)

func TestToGrade_Boundaries(t *testing.T) {
	tests := []struct {
		interlynkScore float64
		want           string
	}{
		{9.5, "A"},
		{9.0, "A"},
		{8.99, "B"},
		{8.0, "B"},
		{7.99, "C"},
		{7.0, "C"},
		{6.0, "D"},
		{5.0, "D"},
		{4.99, "F"},
		{0.0, "F"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, ToGrade(tc.interlynkScore))
	}
}

func TestComputeInterlynkComprScore(t *testing.T) {
	tests := []struct {
		name     string
		input    []api.CategoryResult
		expected float64
	}{
		{
			name: "simple two-category weighted average",
			input: []api.CategoryResult{
				{Key: "identification", Name: "Identification", Weight: 10, Score: 9.0},
				{Key: "provenance", Name: "Provenance", Weight: 12, Score: 7.0},
			},
			expected: (9.0*10.0 + 7.0*12.0) / (10.0 + 12.0),
		},
		{
			name: "excludes compinfo category internally",
			input: []api.CategoryResult{
				{Key: "identification", Weight: 10, Score: 9.0},
				{Key: "provenance", Weight: 12, Score: 7.0},
				{Key: "compinfo", Name: "Component Quality (info)", Weight: 10, Score: 0.0},
			},
			// compinfo should be ignored -> same as simple two-category case
			expected: (9.0*10.0 + 7.0*12.0) / (10.0 + 12.0),
		},
		{
			name: "all zero weights -> returns 0",
			input: []api.CategoryResult{
				{Key: "identification", Weight: 0, Score: 0.5},
				{Key: "provenance", Weight: 0, Score: 0.9},
				// compinfo present but also zero weight - still excluded
				{Key: "compinfo", Weight: 0, Score: 1.0},
			},
			expected: 0.0,
		},
		{
			name: "mix zero and non-zero weights -> only non-zero contribute",
			input: []api.CategoryResult{
				{Key: "zero_cat", Weight: 0, Score: 0.0},
				{Key: "integrity", Weight: 15, Score: 0.8},
				{Key: "compinfo", Weight: 10, Score: 0.0}, // should be ignored
			},
			expected: 0.8, // (0.8 * 15) / 15
		},
		{
			name: "single category -> equals its score",
			input: []api.CategoryResult{
				{Key: "completeness", Weight: 12, Score: 0.42},
			},
			expected: 0.42,
		},
		{
			name: "negative weights (domain-specific) -> demonstrates current behavior",
			input: []api.CategoryResult{
				{Key: "identification", Weight: -5, Score: 1.0},
				{Key: "provenance", Weight: 10, Score: 0.5},
			},
			// current function will compute (1.0 * -5 + 0.5 * 10) / (-5 + 10) = ( -5 + 5 ) / 5 = 0
			// If negative weights are invalid in your domain, you should instead validate earlier.
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeInterlynkComprScore(tt.input)
			assert.InDelta(t, tt.expected, got, 1e-9, "unexpected score for %s", tt.name)
		})
	}
}

func TestPerComponentScore(t *testing.T) {
	got := PerComponentScore(80, 100)
	assert.InDelta(t, 8.0, got, 1e-6)

	got = PerComponentScore(0, 0)
	assert.InDelta(t, 0.0, got, 1e-6)
}

func TestComputeCategoryScore(t *testing.T) {
	tests := []struct {
		name     string
		frs      []api.FeatureResult
		expected float64
	}{
		{
			name: "all ignored -> 0",
			frs: []api.FeatureResult{
				{Key: "f1", Weight: 0.5, Score: 10, Ignored: true},
				{Key: "f2", Weight: 0.5, Score: 0, Ignored: true},
			},
			expected: 0.0,
		},
		{
			name: "with one NA (ignored) -> renormalize remaining weights",
			frs: []api.FeatureResult{
				{Key: "comp_with_name", Weight: 0.40, Score: 10.0, Ignored: false},
				{Key: "comp_with_version", Weight: 0.35, Score: 9.5, Ignored: true}, // N/A
				{Key: "comp_with_identifiers", Weight: 0.25, Score: 8.2, Ignored: false},
			},
			// (10.0*0.40 + 8.2*0.25) / 0.40 + 0.25
			expected: (10.0*0.40 + 8.2*0.25) / 0.65,
		},
		{
			name: "all features active -> normal weighted average",
			frs: []api.FeatureResult{
				{Key: "comp_with_name", Weight: 0.40, Score: 10.0, Ignored: false},
				{Key: "comp_with_version", Weight: 0.35, Score: 9.5, Ignored: false},
				{Key: "comp_with_identifiers", Weight: 0.25, Score: 8.2, Ignored: false},
			},
			// (10.0*0.40 + 9.5*0.35 + 8.2*0.25) / 0.40 + 0.35 + 0.25
			expected: (10.0*0.40 + 9.5*0.35 + 8.2*0.25) / 1.0,
		},
		{
			name: "all zero weights -> returns 0",
			frs: []api.FeatureResult{
				{Key: "a", Weight: 0, Score: 0.5, Ignored: false},
				{Key: "b", Weight: 0, Score: 0.7, Ignored: false},
			},
			expected: 0.0,
		},
		{
			name: "mix of zero and non-zero weights -> only non-zero contribute",
			frs: []api.FeatureResult{
				{Key: "zero_w", Weight: 0, Score: 0.0, Ignored: false},
				{Key: "nonzero", Weight: 3.0, Score: 1.0, Ignored: false},
				{Key: "ignored", Weight: 2.0, Score: 0.5, Ignored: true},
			},
			expected: 1.0, // (1.0*3) / 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeCategoryScore(tt.frs)
			assert.InDelta(t, tt.expected, got, 1e-6, "unexpected score for %s", tt.name)
		})
	}
}
