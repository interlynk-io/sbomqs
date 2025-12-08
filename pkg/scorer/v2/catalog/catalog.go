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

// Package catalog defines the scoring “rulebook” used by sbomqs.
// It describes all comprehensive categories and features, all compliance
// profiles, and the aliases that map human-friendly names to internal keys.
// The catalog is the central source of truth that scoring and compliance
// evaluators use to understand what to check and how to weight it.
package catalog

import (
	"strings"
)

type (
	// ComprCatKey represents a unique identifier for comprehensive scoring categories.
	// These keys are used to reference specific categories like "structural" or "semantic".
	ComprCatKey string

	// ComprFeatKey represents a unique identifier for comprehensive scoring features.
	// These keys are used to reference specific features like "comp-with-name" or "comp-with-version".
	ComprFeatKey string

	// ProfileKey represents a unique identifier for compliance profiles.
	// These keys are used to reference profiles like "ntia" or "bsi-v2.0".
	ProfileKey string

	// ProfFeatKey represents a unique identifier for profile-specific features.
	// These keys are used to reference requirements within a specific profile.
	ProfFeatKey string
)

// Aliases provides human-readable mappings to internal keys for the scoring system.
// It allows users to reference categories, features, and profiles by common names
// instead of internal key identifiers, improving usability and API friendliness.
type Aliases struct {
	Category map[string]ComprCatKey
	Feature  map[string]ComprFeatKey
	Profile  map[string]ProfileKey
}

// Catalog represents the complete specification for SBOM scoring and evaluation.
// It contains all the necessary definitions for comprehensive scoring (categories
// and features with weights) and profile-based evaluation (compliance profiles
// and their requirements). The catalog serves as the central configuration
// for all scoring operations.
type Catalog struct {
	ComprCategories []ComprCatSpec
	ComprFeatures   []ComprFeatSpec
	Profiles        []ProfSpec
	ProfFeatures    []ProfFeatSpec

	Order   []ComprCatSpec
	Aliases Aliases
}

// HasFeature checks if a comprehensive feature with the given key exists in the catalog.
func (c *Catalog) HasFeature(k ComprFeatKey) bool {
	for _, feat := range c.ComprFeatures {
		if feat.Key == string(k) {
			return true
		}
	}
	return false
}

// HasCategory checks if a comprehensive category with the given key exists in the catalog.
func (c *Catalog) HasCategory(k ComprCatKey) bool {
	for _, spec := range c.ComprCategories {
		if string(k) == spec.Key {
			return true
		}
	}
	return false
}

// HasProfile checks if a compliance profile with the given key exists in the catalog.
func (c *Catalog) HasProfile(k ProfileKey) bool {
	for _, pr := range c.Profiles {
		if k == pr.Key {
			return true
		}
	}
	return false
}

// ResolveCategoryAlias converts a human-readable category name to its internal key.
// The lookup is case-insensitive and trims whitespace. Returns the key and
// a boolean indicating whether the alias was found.
func (c *Catalog) ResolveCategoryAlias(s string) (ComprCatKey, bool) {
	k, ok := c.Aliases.Category[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}

// ResolveFeatureAlias converts a human-readable feature name to its internal key.
// The lookup is case-insensitive and trims whitespace. Returns the key and
// a boolean indicating whether the alias was found.
func (c *Catalog) ResolveFeatureAlias(s string) (ComprFeatKey, bool) {
	k, ok := c.Aliases.Feature[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}

// ResolveProfileAlias converts a human-readable profile name to its internal key.
// The lookup is case-insensitive and trims whitespace. Returns the key and
// a boolean indicating whether the alias was found.
func (c *Catalog) ResolveProfileAlias(s string) (ProfileKey, bool) {
	k, ok := c.Aliases.Profile[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}
