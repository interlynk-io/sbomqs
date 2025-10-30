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

package score

import (
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
)

// selectCategoriesToScore returns the list of all categories to score.
func selectCategoriesToScore(cfg config.Config, catal *catalog.Catalog) []catalog.ComprCatKey {
	if len(cfg.Categories) == 0 {
		return catal.BaseCategoriesKeys()
	}
	if len(cfg.Features) == 0 {
		// TODO
	}
	return catal.ResolveCategoryKeys(cfg.Categories)
}
