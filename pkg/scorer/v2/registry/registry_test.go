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

package registry

// func TestCategoryAliases(t *testing.T) {
// 	c := InitializeCatalog()

// 	// HasCategory
// 	cats1 := c.ResolveCategoryKeys([]string{"Identification"})
// 	assert.Equal(t, CatIdentification, cats1[0])

// 	// HasCategory
// 	cats2 := c.ResolveCategoryKeys([]string{"integrity"})
// 	assert.Equal(t, CatIntegrity, cats2[0])

// 	// HasCategory
// 	cats3 := c.ResolveCategoryKeys([]string{"structural"})
// 	assert.Equal(t, CatStructural, cats3[0])

// 	// HasCategory
// 	cats4 := c.ResolveCategoryKeys([]string{"vulnerability"})
// 	assert.Equal(t, CatVulnerabilityAndTrace, cats4[0])

// 	// HasCategory
// 	cats5 := c.ResolveCategoryKeys([]string{"completeness"})
// 	assert.Equal(t, CatCompleteness, cats5[0])

// 	// HasCategory
// 	cats6 := c.ResolveCategoryKeys([]string{"licensing"})
// 	assert.Equal(t, CatLicensingAndCompliance, cats6[0])
// }

// func TestProfileAlias(t *testing.T) {
// 	c := InitializeCatalog()

// 	pr := []string{"bsi-v1.1", "ntia"}
// 	pk := c.ResolveProfileKeys(pr)
// 	assert.Equal(t, ProfileBSI11, pk[0])
// 	assert.Equal(t, ProfileNTIA, pk[1])

// 	assert.True(t, c.HasProfile(c.ResolveProfileKeys([]string{"bsi-v2.0"})[0]))
// 	assert.True(t, c.HasProfile(pk[0]))
// }
