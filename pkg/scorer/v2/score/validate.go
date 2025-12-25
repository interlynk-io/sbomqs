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
	"context"
	"os"
	"path/filepath"
	"sort"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/utils"
	"go.uber.org/zap"
)

// validateAndExpandPaths returns a list of files and URLs.
// - URLs are kept as-is (no normalization here).
// - Directories are expanded to one leve only by default
// - If recursive is true, directories are walked recursively.
func validateAndExpandPaths(ctx context.Context, paths []string, recursive bool) []string {
	log := logger.FromContext(ctx)
	log.Debug("Validating and expanding input paths",
		zap.Int("input", len(paths)),
	)

	validPaths := make([]string, 0, len(paths))
	alreadyExist := utils.Set[string]{}

	for _, path := range paths {
		if utils.IsBlank(path) {
			continue
		}

		// accept URLs
		if utils.IsURL(path) {
			utils.AppendUnique(&validPaths, alreadyExist, path)
			continue
		}

		// accept existing local files/dirs
		info, err := os.Stat(path)
		if err != nil {
			log.Debug("Skipping path: cannot stat",
				zap.String("path", path),
				zap.Error(err),
			)
			continue
		}

		switch {
		// files: add directly.
		case info.Mode().IsRegular():
			utils.AppendUnique(&validPaths, alreadyExist, path)

			// irs: expand to files.
		case info.IsDir():

			if recursive {
				// recursive walk into sub-dir
				err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
					if err != nil {
						log.Debug("skip: cannot access", zap.String("path", p), zap.Error(err))
						return nil
					}

					if d.Type().IsRegular() {
						utils.AppendUnique(&validPaths, alreadyExist, p)
					}

					return nil
				})
				if err != nil {
					log.Debug("skip: cannot access", zap.String("path", path), zap.Error(err))
				}
				continue
			}

			// non-recursive (existing behavior)
			files, err := os.ReadDir(path)
			if err != nil {
				log.Debug("Skipping directory: cannot read",
					zap.String("path", path),
					zap.Error(err),
				)
				continue
			}

			for _, file := range files {
				if file.Type().IsRegular() {
					utils.AppendUnique(&validPaths, alreadyExist, filepath.Join(path, file.Name()))
				}
			}

		default:
			log.Debug("Skipping unsupported path type",
				zap.String("path", path),
			)
		}
	}

	// optional: ensure deterministic order (helps tests & diffs)
	sort.Strings(validPaths)

	log.Debug("Path validation completed",
		zap.Int("valid", len(validPaths)),
	)
	return validPaths
}

// containsDirectory reports whether the "paths" includes at least one directory path.
func containsDirectory(paths []string) bool {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			return true
		}
	}
	return false
}

// // validateConfig verifies that user-supplied categories, features (and profiles) exist in the catalog.
// // It normalizes inputs via alias resolution, preserves order, de-duplicates, and errors on unknowns.
// func validateConfig(ctx context.Context, catal *catalog.Catalog, cfg *config.Config) error {
// 	log := logger.FromContext(ctx)
// 	log.Debug("validating configuration")

// 	if cfg.ConfigFile != "" {
// 		if _, err := os.Stat(cfg.ConfigFile); err != nil {
// 			return fmt.Errorf("invalid config path %q: %w", cfg.ConfigFile, err)
// 		}
// 		return nil
// 	}

// 	cfg.Categories = utils.RemoveEmptyStrings(cfg.Categories)

// 	var (
// 		normCats   []string
// 		unknownCat []string
// 		seenCat    = make(map[string]struct{})
// 	)

// 	for _, cat := range cfg.Categories {
// 		if k, ok := catal.ResolveCategoryAlias(cat); ok && catal.HasCategory(k) {
// 			ck := string(k)
// 			utils.AppendUnique(&normCats, seenCat, ck)
// 		} else {
// 			unknownCat = append(unknownCat, cat)
// 		}
// 	}

// 	if len(unknownCat) > 0 {
// 		return fmt.Errorf("unknown categories: %s", strings.Join(unknownCat, ", "))
// 	}
// 	cfg.Categories = normCats

// 	// --- Features ---
// 	cfg.Features = utils.RemoveEmptyStrings(cfg.Features)

// 	var (
// 		normFeats   []string
// 		unknownFeat []string
// 		seenFeat    = make(map[string]struct{})
// 	)

// 	for _, raw := range cfg.Features {
// 		if k, ok := catal.ResolveFeatureAlias(raw); ok && catal.HasFeature(k) {
// 			fk := string(k)
// 			utils.AppendUnique(&normFeats, seenFeat, fk)
// 		} else {
// 			unknownFeat = append(unknownFeat, raw)
// 		}
// 	}

// 	if len(unknownFeat) > 0 {
// 		return fmt.Errorf("unknown features: %s", strings.Join(unknownFeat, ", "))
// 	}
// 	cfg.Features = normFeats

// 	if len(cfg.Profile) > 0 {
// 		var (
// 			normProfiles []string
// 			unknownProf  []string
// 			seenProf     = make(map[string]struct{})
// 		)
// 		for _, raw := range utils.RemoveEmptyStrings(cfg.Profile) {
// 			if k, ok := catal.ResolveProfileAlias(raw); ok && catal.HasProfile(k) {
// 				pk := string(k)
// 				utils.AppendUnique(&normProfiles, seenProf, pk)
// 			} else {
// 				unknownProf = append(unknownProf, raw)
// 			}
// 		}
// 		if len(unknownProf) > 0 {
// 			return fmt.Errorf("unknown profiles: %s", strings.Join(unknownProf, ", "))
// 		}
// 		cfg.Profile = normProfiles
// 	}

// 	log.Debugf("validated config: categories=%v features=%v profiles=%v", cfg.Categories, cfg.Features, cfg.Profile)
// 	return nil
// }
