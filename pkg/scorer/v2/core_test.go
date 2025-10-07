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

func catNames(cs []CategorySpec) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func featKeys(fs []FeatureSpec) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}

func TestFilterCategories(t *testing.T) {
	// Common input set for the cases below
	input := []CategorySpec{
		{
			Name:   "Identification",
			Weight: 10,
			Features: []FeatureSpec{
				{
					Key:    "comp_with_name",
					Weight: 0.40,
				},
				{
					Key:    "comp_with_version",
					Weight: 0.35,
				},
				{
					Key:    "comp_with_ids",
					Weight: 0.25,
				},
			},
		},
		{
			Name:   "Provenance",
			Weight: 12,
			Features: []FeatureSpec{
				{
					Key:    "sbom_creation_timestamp",
					Weight: 0.20,
				},
				{
					Key:    "sbom_authors",
					Weight: 0.20,
				},
			},
		},
	}

	tests := []struct {
		name           string
		cfg            Config
		categories     []CategorySpec
		wantCatNames   []string            // expected categories (order preserved)
		wantCatFeatMap map[string][]string // expected feature keys per kept category (order preserved)
	}{
		{
			name:         "No filters",
			cfg:          Config{},
			categories:   input,
			wantCatNames: []string{"Identification", "Provenance"},
			wantCatFeatMap: map[string][]string{
				"Identification": {"comp_with_name", "comp_with_version", "comp_with_ids"},
				"Provenance":     {"sbom_creation_timestamp", "sbom_authors"},
			},
		},
		{
			name:       "Filter Identification category",
			cfg:        Config{Categories: []string{"Identification"}},
			categories: input,
			wantCatNames: []string{
				"Identification",
			},
			wantCatFeatMap: map[string][]string{
				"Identification": {"comp_with_name", "comp_with_version", "comp_with_ids"},
			},
		},
		{
			name:       "By features → keep only categories that have those features (and only those features)",
			cfg:        Config{Features: []string{"comp_with_name", "comp_with_version"}},
			categories: input,
			wantCatNames: []string{
				"Identification",
			},
			wantCatFeatMap: map[string][]string{
				"Identification": {"comp_with_name", "comp_with_version"},
			},
		},
		{
			name:       "Both category and features → intersection",
			cfg:        Config{Categories: []string{"Provenance"}, Features: []string{"sbom_authors", "not_present"}},
			categories: input,
			wantCatNames: []string{
				"Provenance",
			},
			wantCatFeatMap: map[string][]string{
				"Provenance": {"sbom_authors"},
			},
		},
		{
			name:       "Feature filter removes all features from a category → category dropped",
			cfg:        Config{Features: []string{"nonexistent_feature"}},
			categories: input,
			// No categories should remain
			wantCatNames:   []string{},
			wantCatFeatMap: map[string][]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterCategories(tc.cfg, tc.categories)

			assert.Equal(t, tc.wantCatNames, catNames(got))

			for _, c := range got {
				want, ok := tc.wantCatFeatMap[c.Name]
				if !ok {
					t.Fatalf("unexpected category in output: %q", c.Name)
				}
				assert.Equal(t, want, featKeys(c.Features), "features in category %q mismatch", c.Name)
			}

			assert.Equal(t, len(tc.wantCatFeatMap), len(got))
		})
	}
}
