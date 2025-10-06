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
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
)

var CategoryAliases = map[string]string{
	"identification": "Identification",
	"provenance":     "Provenance",
	"integrity":      "Integrity",
	"completeness":   "Completeness",
	"licensing":      "Licensing",
	"vulnerability":  "Vulnerability",
	"structural":     "Structural",
}

var SupportedCategories = map[string]bool{
	"Identification": true,
	"Provenance":     true,
	"Integrity":      true,
	"Completeness":   true,
	"Licensing":      true,
	"Vulnerability":  true,
	"Structural":     true,
}

var SupportedFeatures = map[string]bool{
	"comp_with_name":             true,
	"comp_with_version":          true,
	"comp_with_identifiers":      true,
	"sbom_creation_timestamp":    true,
	"sbom_authors":               true,
	"sbom_tool_version":          true,
	"sbom_supplier":              true,
	"sbom_namespace":             true,
	"sbom_lifecycle":             true,
	"comp_with_checksums":        true,
	"comp_with_sha256":           true,
	"sbom_signature":             true,
	"comp_with_dependencies":     true,
	"sbom_completeness_declared": true,
	"primary_component":          true,
	"comp_with_source_code":      true,
	"comp_with_supplier":         true,
	"comp_with_purpose":          true,
	"comp_with_licenses":         true,

	"comp_with_valid_licenses":     true,
	"comp_with_declared_licenses":  true,
	"sbom_data_license":            true,
	"comp_no_deprecated_licenses":  true,
	"comp_no_restrictive_licenses": true,
	"comp_with_purl":               true,
	"comp_with_cpe":                true,
	"sbom_spec_declared":           true,
	"sbom_spec_version":            true,
	"sbom_file_format":             true,
	"sbom_schema_valid":            true,
}

func validateFeatures(ctx context.Context, features []string) ([]string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("validating features: %v", features)

	var validFeatures []string

	for _, feature := range features {
		if _, ok := SupportedFeatures[feature]; !ok {
			log.Warnf("unsupported feature: %s", feature)
			continue
		}
		validFeatures = append(validFeatures, feature)
	}
	return validFeatures, nil
}

// isHTTPURL returns true for well-formed http(s) URLs.
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != "" && strings.TrimSpace(u.Path) != ""
}

// validateAndExpandPaths returns only files and URLs.
// - URLs are kept as-is.
// - URLs are kept as-is.
// - Directories are expanded to their files (non-recursive by default; set recurse=true for walk).
// - Directories are expanded to their files (non-recursive by default; set recurse=true for walk).
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
		if isHTTPURL(path) {
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

func validateConfig(ctx context.Context, config *Config) error {
	log := logger.FromContext(ctx)
	log.Debug("validating configuration")

	if config.ConfigFile != "" {
		if _, err := os.Stat(config.ConfigFile); err != nil {
			return fmt.Errorf("invalid config path: %s: %w", config.ConfigFile, err)
		}
		return nil
	}
	config.Categories = removeEmptyStrings(config.Categories)

	if len(config.Categories) > 0 {
		normCategories, err := normalizeAndValidateCategories(ctx, config.Categories)
		if err != nil {
			return fmt.Errorf("failed to normalize and validate categories: %w", err)
		}
		config.Categories = normCategories
	}

	config.Features = removeEmptyStrings(config.Features)
	if len(config.Features) > 0 {
		validFeatures, err := validateFeatures(ctx, config.Features)
		if err != nil {
			return fmt.Errorf("failed to validate features: %w", err)
		}
		config.Features = validFeatures
	}

	return nil
}
