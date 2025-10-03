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
	"os"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
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

// validatePaths returns the valid paths.
func validatePaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debug("validating paths")

	var validPaths []string

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			log.Debugf("skipping invalid path: %s, error: %v", path, err)
			continue
		}
		validPaths = append(validPaths, path)
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
	config.Categories = RemoveEmptyStrings(config.Categories)

	if len(config.Categories) > 0 {
		log.Debugf("validating categories: %v", config.Categories)
		normCategories, err := normalizeAndValidateCategories(ctx, config.Categories)
		if err != nil {
			return fmt.Errorf("failed to normalize and validate categories: %w", err)
		}
		config.Categories = normCategories
	}

	config.Features = RemoveEmptyStrings(config.Features)
	if len(config.Features) > 0 {
		log.Debugf("validating features: %v", config.Features)
		validFeatures, err := validateFeatures(ctx, config.Features)
		if err != nil {
			return fmt.Errorf("failed to validate features: %w", err)
		}
		config.Features = validFeatures
	}

	return nil
}

// getFileHandle opens a file in read-only mode and returns the handle.
// The caller is responsible for calling Close() on the returned file.
func getFileHandle(ctx context.Context, filePath string) (*os.File, error) {
	log := logger.FromContext(ctx)

	log.Debugf("Opening file for reading: %q", filePath)

	file, err := os.Open(filePath) // read-only
	if err != nil {
		log.Debugf("Failed to open %q: %v", filePath, err)
		return nil, fmt.Errorf("open file for reading: %q: %w", filePath, err)
	}

	log.Debugf("Successfully opened %q", filePath)
	return file, nil
}

func getSignature(ctx context.Context, path string, sigValue, publicKey string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

	if sigValue == "" || publicKey == "" {
		return sbom.Signature{}, nil
	}
	blob, signature, pubKey, err := common.GetSignatureBundle(ctx, path, sigValue, publicKey)
	if err != nil {
		log.Debugf("failed to get signature bundle for file: %s: %v", path, err)
		return sbom.Signature{}, err
	}

	return sbom.Signature{
		SigValue:  signature,
		PublicKey: pubKey,
		Blob:      blob,
	}, nil
}
