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

// import (
// 	"testing"

// 	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
// 	"github.com/stretchr/testify/assert"
// )

// func TestHastersAndResolveAliases(t *testing.T) {
// 	c := registry.InitializeCatalog()
// 	// HasFeature
// 	assert.True(t, c.HasFeature("comp_with_name"))
// 	assert.True(t, c.HasFeature(ComprFeatKey("comp_with_version")))
// 	assert.False(t, c.HasFeature("does-not-exist"))

// 	// HasCategory
// 	assert.True(t, c.HasCategory("Identification"))
// 	assert.True(t, c.HasCategory(ComprCatKey("Integrity")))
// 	assert.False(t, c.HasCategory("UnknownCat"))

// 	// HasProfile
// 	assert.True(t, c.HasProfile("ntia"))
// 	assert.True(t, c.HasProfile(ProfileKey("bsi-v2.0")))
// 	assert.False(t, c.HasProfile(ProfileKey("unknown")))

// 	// ResolveFeatureAlias (alias exists)
// 	k, ok := c.ResolveFeatureAlias("name")
// 	assert.True(t, ok)
// 	assert.Equal(t, ComprFeatKey("comp_with_name"), k)

// 	// ResolveCategoryAlias (alias exists, case/space tolerant)
// 	ck, ok := c.ResolveCategoryAlias("  IDENT ")
// 	assert.True(t, ok)
// 	assert.Equal(t, ComprCatKey("Identification"), ck)

// 	// ResolveProfileAlias (alias exists)
// 	pk, ok := c.ResolveProfileAlias("bsi")
// 	assert.True(t, ok)
// 	assert.Equal(t, ProfileKey("bsi-v2.0"), pk)

// 	// ResolveProfileAlias not found
// 	_, ok = c.ResolveProfileAlias("nope")
// 	assert.False(t, ok)
// }
