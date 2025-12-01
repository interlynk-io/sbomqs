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
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/v2/pkg/utils"
)

// ProcessURLPath downloads an SBOM from a URL and returns a temporary file handle.
// It handles both regular URLs and Git repository URLs, downloading the SBOM
// content and storing it in a temporary file for processing. The caller is
// responsible for closing the file and cleaning up the temporary file.
//
// Parameters:
//   - ctx: Context for cancellation and logging
//   - cfg: Configuration (currently unused but maintained for API consistency)
//   - url: URL pointing to an SBOM file or Git repository
//
// Returns a file handle to the downloaded SBOM content, or an error if
// the download or file creation fails.
func ProcessURLPath(ctx context.Context, cfg config.Config, url string) (*os.File, error) {
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
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to write to temp SBOM file: %w", err)
	}

	// Rewind file pointer for reading later
	if _, err := tmpFile.Seek(0, 0); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to reset temp file pointer: %w", err)
	}

	return tmpFile, nil
}

// GetFileHandle opens a file in read-only mode and returns the file handle.
// This function provides a simple wrapper around os.Open with logging support.
// The caller is responsible for calling Close() on the returned file to
// prevent resource leaks.
//
// Parameters:
//   - ctx: Context for cancellation and logging
//   - filePath: Path to the file to be opened
//
// Returns a file handle opened for reading, or an error if the file
// cannot be opened.
func GetFileHandle(ctx context.Context, filePath string) (*os.File, error) {
	log := logger.FromContext(ctx)

	log.Debugf("Opening file for reading: %q", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		log.Debugf("Failed to open %q: %v", filePath, err)
		return nil, fmt.Errorf("open file for reading: %q: %w", filePath, err)
	}

	log.Debugf("Successfully opened %q", filePath)
	return file, nil
}

// ExtractSignature extracts cryptographic signature information for SBOM verification.
// It retrieves signatures either from external configuration or from the SBOM
// itself (in the case of CycloneDX format). If no signature configuration is
// provided, it returns an empty signature without error.
//
// Parameters:
//   - ctx: Context for cancellation and logging
//   - cfg: Configuration containing signature bundle information
//   - path: Path to the SBOM file for signature extraction
//
// Returns a Signature containing validation data, or an empty signature
// if no signature configuration is available.
func ExtractSignature(ctx context.Context, cfg config.Config, path string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

	sigValue, publicKey := cfg.SignatureBundle.SigValue, cfg.SignatureBundle.PublicKey
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

// CategoryNames extracts the display names from a slice of comprehensive category specifications.
// This utility function is primarily used for logging and debugging purposes to provide
// human-readable category names.
//
// Parameters:
//   - cats: Slice of comprehensive category specifications
//
// Returns a slice of category names in the same order as the input specifications.
func CategoryNames(cats []catalog.ComprCatSpec) []string {
	out := make([]string, 0, len(cats))
	for _, c := range cats {
		out = append(out, c.Name)
	}
	return out
}
