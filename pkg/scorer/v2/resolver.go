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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

func processURLPath(ctx context.Context, config Config, url string) (*os.File, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing URL: %s", url)

	if utils.IsGit(url) {
		_, rawURL, err := utils.HandleURL(url)
		if err != nil {
			return nil, fmt.Errorf("handleURL failed: %w", err)
		}
		url = rawURL
	}

	// download SBOM data from the URL
	sbomData, err := utils.DownloadSBOMFromURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download SBOM from URL %s: %w", url, err)
	}

	// create a temporary file to store the SBOM
	tmpFile, err := os.CreateTemp("", "sbomqs-url-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for SBOM: %w", err)
	}

	if _, err := tmpFile.Write(sbomData); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to write to temp SBOM file: %w", err)
	}

	// Rewind file pointer for reading later
	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to reset temp file pointer: %w", err)
	}

	return tmpFile, nil
}

func removeEmptyStrings(input []string) []string {
	var output []string
	for _, s := range input {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	return output
}

func normalizeAndValidateCategories(ctx context.Context, categories []string) ([]string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("normalizing anf validating categories: %s", categories)
	var normalized []string

	for _, cat := range categories {

		// normalize using alias
		if alias, ok := CategoryAliases[cat]; ok {
			cat = alias
		}

		// validate if it's a supported category
		if !SupportedCategories[cat] {
			log.Warnf("unsupported category: %s", cat)
			continue
		}
		normalized = append(normalized, cat)
	}

	return normalized, nil
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

func getSignature(ctx context.Context, config Config, path string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

	sigValue, publicKey := config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey
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

// helper for logging
func categoryNames(cats []CategorySpec) []string {
	out := make([]string, 0, len(cats))
	for _, c := range cats {
		out = append(out, c.Name)
	}
	return out
}
