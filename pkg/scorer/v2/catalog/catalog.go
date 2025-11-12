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

package catalog

import (
	"strings"
)

type (
	// comprehenssive cateogy and it's features keys
	ComprCatKey  string
	ComprFeatKey string

	// profiles and it's feature keys
	ProfileKey  string
	ProfFeatKey string
)

// Aliases represent mapping of common name to keys
type Aliases struct {
	Category map[string]ComprCatKey
	Feature  map[string]ComprFeatKey
	Profile  map[string]ProfileKey
}

// Catalog is a collection of comprehenssive categories, features
// and profiles and it's features
type Catalog struct {
	ComprCategories []ComprCatSpec
	ComprFeatures   []ComprFeatSpec
	Profiles        []ProfSpec
	ProfFeatures    []ProfFeatSpec

	Order   []ComprCatSpec
	Aliases Aliases
}

func (c *Catalog) HasFeature(k ComprFeatKey) bool {
	for _, feat := range c.ComprFeatures {
		if feat.Key == string(k) {
			return true
		}
	}
	return false
}

func (c *Catalog) HasCategory(k ComprCatKey) bool {
	for _, spec := range c.ComprCategories {
		if string(k) == spec.Key {
			return true
		}
	}
	return false
}

func (c *Catalog) HasProfile(k ProfileKey) bool {
	for _, pr := range c.Profiles {
		if k == pr.Key {
			return true
		}
	}
	return false
}

func (c *Catalog) ResolveCategoryAlias(s string) (ComprCatKey, bool) {
	k, ok := c.Aliases.Category[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}

func (c *Catalog) ResolveFeatureAlias(s string) (ComprFeatKey, bool) {
	k, ok := c.Aliases.Feature[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}

func (c *Catalog) ResolveProfileAlias(s string) (ProfileKey, bool) {
	k, ok := c.Aliases.Profile[strings.ToLower(strings.TrimSpace(s))]
	return k, ok
}
