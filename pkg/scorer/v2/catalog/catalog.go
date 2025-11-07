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

	"github.com/interlynk-io/sbomqs/pkg/utils"
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
	ComprFeatures   map[ComprFeatKey]ComprFeatSpec
	ComprCategories map[ComprCatKey]ComprCatSpec

	Profiles     map[ProfileKey]ProfSpec
	ProfFeatures map[ProfFeatKey]ProfFeatSpec

	Order   []ComprCatKey
	Aliases Aliases
}

func (c *Catalog) HasFeature(k ComprFeatKey) bool {
	_, ok := c.ComprFeatures[k]
	return ok
}

func (c *Catalog) HasCategory(k ComprCatKey) bool {
	_, ok := c.ComprCategories[k]
	return ok
}

func (c *Catalog) HasProfile(k ProfileKey) bool {
	_, ok := c.Profiles[k]
	return ok
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

func (c *Catalog) BaseCategoriesKeys() []ComprCatKey {
	return c.Order
}

func (c *Catalog) BaseCategoriesSpec() []ComprCatSpec {
	catKeys := c.BaseCategoriesKeys()
	allCategories := make([]ComprCatSpec, 0, len(catKeys))
	for _, key := range catKeys {
		category, ok := c.ComprCategories[key]
		if ok {
			allCategories = append(allCategories, category)
		}
	}
	return allCategories
}

func (c *Catalog) BaseProfiles() []ProfSpec {
	out := make([]ProfSpec, 0, len(c.Profiles))
	for _, k := range c.Profiles {
		out = append(out, k)
	}
	return out
}

// ResolveProfileKeys converts user-provided strings into ProfileKeys.
// 1) Tries alias map first (Catalog.Aliases.Profile).
// 2) Then tries exact key (case-insensitive).
// 3) Then tries profile display name (ProfSpec.Name, case-insensitive).
// 4) Preserves input order and de-duplicates.
func (c *Catalog) ResolveProfileKeys(profiles []string) []ProfileKey {
	if c == nil || len(profiles) == 0 {
		return nil
	}

	profileKeys := make([]ProfileKey, 0, len(profiles))
	alreadyExist := make(map[ProfileKey]struct{}, len(profiles))

	// Build lookups for exact key and display name.
	exactProfileKey := make(map[string]ProfileKey, len(c.Profiles)) // "bsi-v2.0" -> ProfileBSI20
	byProfileName := make(map[string]ProfileKey, len(c.Profiles))   // "BSI-V2.0" -> ProfileBSI20

	for pKey, spec := range c.Profiles {
		exactProfileKey[strings.ToLower(string(pKey))] = pKey
		if spec.Name != "" {
			byProfileName[strings.ToLower(spec.Name)] = pKey
		}
	}

	for _, pr := range profiles {
		if utils.IsBlank(pr) {
			continue
		}
		input := strings.ToLower(strings.TrimSpace(pr))

		var (
			pk ProfileKey
			ok bool
		)

		// 1) alias (aliases are already stored lowercased)
		// 2) exact key (case-insensitive)
		// 3) profile display name (case-insensitive)
		if pk, ok = c.Aliases.Profile[input]; !ok {
			if pk, ok = exactProfileKey[input]; !ok {
				if pk, ok = byProfileName[input]; !ok {
					continue // skip
				}
			}
		}

		if _, dup := alreadyExist[pk]; dup {
			continue
		}
		alreadyExist[pk] = struct{}{}
		profileKeys = append(profileKeys, pk)
	}

	return profileKeys
}

// ResolveProfileKeys converts user-provided strings into ProfileKeys.
// 1) Tries alias map first (Catalog.Aliases.Profile).
// 2) Then tries exact key (case-insensitive).
// 3) Then tries profile display name (ProfSpec.Name, case-insensitive).
// 4) Preserves input order and de-duplicates.
func (c *Catalog) ResolveCategoryKeys(category []string) []ComprCatKey {
	if c == nil || len(category) == 0 {
		return nil
	}

	catKeys := make([]ComprCatKey, 0, len(category))
	alreadyExist := make(map[ComprCatKey]struct{}, len(category))

	// Build lookups for exact key and display name.
	exactCatKey := make(map[string]ComprCatKey, len(c.ComprCategories)) // "bsi-v2.0" -> ProfileBSI20
	byCatName := make(map[string]ComprCatKey, len(c.ComprCategories))   // "BSI-V2.0" -> ProfileBSI20

	for key, spec := range c.ComprCategories {
		exactCatKey[strings.ToLower(string(key))] = key
		if spec.Name != "" {
			byCatName[strings.ToLower(spec.Name)] = key
		}
	}

	for _, cat := range category {
		if utils.IsBlank(cat) {
			continue
		}
		input := strings.ToLower(strings.TrimSpace(cat))

		var (
			pk ComprCatKey
			ok bool
		)

		// 1) alias (aliases are already stored lowercased)
		// 2) exact key (case-insensitive)
		// 3) profile display name (case-insensitive)
		if pk, ok = c.Aliases.Category[input]; !ok {
			if pk, ok = exactCatKey[input]; !ok {
				if pk, ok = byCatName[input]; !ok {
					continue // skip
				}
			}
		}

		if _, dup := alreadyExist[pk]; dup {
			continue
		}
		alreadyExist[pk] = struct{}{}
		catKeys = append(catKeys, pk)
	}

	return catKeys
}
