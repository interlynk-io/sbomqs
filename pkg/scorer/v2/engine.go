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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func ScoreSBOM(ctx context.Context, config Config, paths []string) ([]ScoreResult, error) {
	log := logger.FromContext(ctx)
	var results []ScoreResult
	var anyProcessed bool

	// Validate paths
	validPaths := validatePaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// Validate config
	if err := validateConfig(ctx, &config); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	// 3) Process each valid input
	log.Debugf("processing %d SBOM inputs", len(validPaths))

	for _, p := range validPaths {
		switch {
		case IsURL(p):
			log.Debugf("processing URL: %s", p)

			sbomFile, sig, err := processURLInput(ctx, p, config) // returns *os.File (temp) + signature bundle
			if err != nil {
				log.Warnf("failed to process URL %s: %v", p, err)
				continue
			}
			func() { // ensure cleanup per-iteration
				defer func() {
					_ = sbomFile.Close()
					_ = os.Remove(sbomFile.Name())
				}()
				res, err := processSBOMInput(ctx, sbomFile, sig, config, p)
				if err != nil {
					log.Warnf("failed to score SBOM from URL %s: %v", p, err)
					return
				}
				results = append(results, res)
				anyProcessed = true
			}()

		case IsDir(p):
			log.Debugf("processing directory: %s", p)
			dirResults := processDirectory(ctx, p, config) // []ScoreResult (skip bad files internally)
			if len(dirResults) > 0 {
				results = append(results, dirResults...)
				anyProcessed = true
			}

		default:
			if _, err := os.Stat(p); err != nil {
				log.Warnf("cannot stat path %s: %v", p, err)
				continue
			}
			log.Debugf("processing file: %s", p)

			f, err := getFileHandle(ctx, p) // *os.File
			if err != nil {
				log.Warnf("failed to open file %s: %v", p, err)
				continue
			}
			func() {
				defer f.Close()

				sig, err := getSignature(ctx, p, config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey)
				if err != nil {
					log.Warnf("failed to get signature for %s: %v", p, err)
					return
				}
				res, err := processSBOMInput(ctx, f, sig, config, p)
				if err != nil {
					log.Warnf("failed to process SBOM %s: %v", p, err)
					return
				}
				results = append(results, res)
				anyProcessed = true
			}()
		}
	}

	if !anyProcessed {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}
	return results, nil
}

func processURLInput(ctx context.Context, url string, config Config) (*os.File, sbom.Signature, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing URL: %s", url)

	if IsGit(url) {
		_, rawURL, err := HandleURL(url)
		if err != nil {
			return nil, sbom.Signature{}, fmt.Errorf("handleURL failed: %w", err)
		}
		url = rawURL
	}

	// download SBOM data from the URL
	data, err := DownloadURL(url)
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to download SBOM from URL %s: %w", url, err)
	}

	// create a temporary file to store the SBOM
	tmpFile, err := os.CreateTemp("", "sbomqs-url-*.json")
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to create temp file for SBOM: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to write to temp SBOM file: %w", err)
	}

	// Rewind file pointer for reading later
	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to reset temp file pointer: %w", err)
	}

	sig := sbom.Signature{
		SigValue:  config.SignatureBundle.SigValue,
		PublicKey: config.SignatureBundle.PublicKey,
	}

	return tmpFile, sig, nil
}
