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

package v2

import (
	"testing"

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
		assert.Equal(t, tc.want, toGrade(tc.interlynkScore))
	}
}

func TestComputeInterlynkScore(t *testing.T) {
	// overall = (9*10 + 7*12) / (10+12) = 7.909090...
	catResults := []CategoryResult{
		{Name: "Identification", Weight: 10, Score: 9.0},
		{Name: "Provenance", Weight: 12, Score: 7.0},
	}

	got := computeInterlynkScore(catResults)
	want := (9.0*10.0 + 7.0*12.0) / (10.0 + 12.0)

	assert.InDelta(t, want, got, 1e-6)
}

func TestComputeCategoryScore_AllNA(t *testing.T) {
	frs := []FeatureResult{
		{Key: "f1", Weight: 0.5, Score: 10, Ignored: true},
		{Key: "f2", Weight: 0.5, Score: 0, Ignored: true},
	}
	want := 0.0
	got := computeCategoryScore(frs)

	assert.InDelta(t, want, got, 1e-6)
}

func TestComputeCategoryScore_WithNA(t *testing.T) {
	// middle feature will be ignored; renormalize 0.40 and 0.25 = sum 0.65
	frs := []FeatureResult{
		{Key: "comp_with_name", Weight: 0.40, Score: 10.0, Ignored: false},
		{Key: "comp_with_version", Weight: 0.35, Score: 9.5, Ignored: true}, // N/A
		{Key: "comp_with_identifiers", Weight: 0.25, Score: 8.2, Ignored: false},
	}
	got := computeCategoryScore(frs)
	want := (10.0*0.40 + 8.2*0.25) / 0.65

	assert.InDelta(t, want, got, 1e-6)
}

func TestComputeCategoryScore(t *testing.T) {
	frs := []FeatureResult{
		{Key: "comp_with_name", Weight: 0.40, Score: 10.0, Ignored: false},
		{Key: "comp_with_version", Weight: 0.35, Score: 9.5, Ignored: false},
		{Key: "comp_with_identifiers", Weight: 0.25, Score: 8.2, Ignored: false},
	}
	got := computeCategoryScore(frs)
	want := (10.0*0.40 + 9.5*0.35 + 8.2*0.25) / 1.0

	assert.InDelta(t, want, got, 1e-6)
}

func TestPerComponentScore(t *testing.T) {
	got := perComponentScore(80, 100)
	assert.InDelta(t, 8.0, got, 1e-6)

	got = perComponentScore(0, 0)
	assert.InDelta(t, 0.0, got, 1e-6)
}
