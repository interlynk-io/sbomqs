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

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

func validateFeatures(ctx context.Context, features []string) ([]string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("validating features: %v", features)

	var validFeatures []string

	for _, feature := range features {
		if _, ok := registry.SupportedFeatures[feature]; !ok {
			log.Warnf("unsupported feature: %s", feature)
			continue
		}
		validFeatures = append(validFeatures, feature)
	}
	return validFeatures, nil
}

// validateAndExpandPaths returns only files and URLs.
// - URLs are kept as-is.
// - Directories are expanded to their files
func validateAndExpandPaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debug("validating paths")

	validPaths := make([]string, 0, len(paths))
	check := make(map[string]bool)

	for _, path := range paths {

		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		// accept URLs
		if utils.IsURL(path) {
			if !check[path] {
				check[path] = true
				validPaths = append(validPaths, path)
			}
			continue
		}

		// accept existing local files/dirs
		info, err := os.Stat(path)
		if err != nil {
			log.Debugf("skip: cannot stat %q: %v", path, err)
			continue
		}

		// Files: add directly.
		if info.Mode().IsRegular() {
			if !check[path] {
				check[path] = true
				validPaths = append(validPaths, path)
			}
			continue
		}

		// Dirs: expand to files.
		if info.IsDir() {
			files, err := os.ReadDir(path)
			if err != nil {
				log.Debugf("skip: cannot read dir %q: %v", path, err)
				continue
			}
			for _, file := range files {
				if file.Type().IsRegular() {
					fullPath := filepath.Join(path, file.Name())
					if !check[fullPath] {
						check[fullPath] = true
						validPaths = append(validPaths, fullPath)
					}
				}
			}
			continue
		}

		log.Debugf("skip: unsupported path type %q", path)
	}

	return validPaths
}

func validateConfig(ctx context.Context, cfg *config.Config) error {
	log := logger.FromContext(ctx)
	log.Debug("validating configuration")

	if cfg.ConfigFile != "" {
		if _, err := os.Stat(cfg.ConfigFile); err != nil {
			return fmt.Errorf("invalid config path: %s: %w", cfg.ConfigFile, err)
		}
		return nil
	}
	cfg.Categories = removeEmptyStrings(cfg.Categories)

	if len(cfg.Categories) > 0 {
		normCategories, err := normalizeAndValidateCategories(ctx, cfg.Categories)
		if err != nil {
			return fmt.Errorf("failed to normalize and validate categories: %w", err)
		}
		cfg.Categories = normCategories
	}

	cfg.Features = removeEmptyStrings(cfg.Features)
	if len(cfg.Features) > 0 {
		validFeatures, err := validateFeatures(ctx, cfg.Features)
		if err != nil {
			return fmt.Errorf("failed to validate features: %w", err)
		}
		cfg.Features = validFeatures
	}

	return nil
}
