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

func ScoreSBOM(ctx context.Context, config Config, paths []string) ([]Result, error) {
	log := logger.FromContext(ctx)

	// var results []Result
	// var anyProcessed bool

	// Validate paths
	validPaths := validatePaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// Validate config
	if err := validateConfig(ctx, &config); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	results := make([]Result, 0, len(validPaths))
	var anyProcessed bool

	for _, path := range validPaths {
		switch {
		case IsURL(path):
			log.Debugf("processing URL: %s", path)

			// sbomFile, sig, err := processURLInput(ctx, p, config)
			// if err != nil {
			// 	log.Warnf("failed to process URL %s: %v", p, err)
			// 	continue
			// }
			// func() {
			// 	defer func() {
			// 		_ = sbomFile.Close()
			// 		_ = os.Remove(sbomFile.Name())
			// 	}()
			// 	res, err := processSBOMInput(ctx, sbomFile, sig, config, p)
			// 	if err != nil {
			// 		log.Warnf("failed to score SBOM from URL %s: %v", p, err)
			// 		return
			// 	}
			// 	results = append(results, res)
			// 	anyProcessed = true
			// }()

		case IsDir(path):
			// dirResults := processDirectory(ctx, p, config)
			// if len(dirResults) > 0 {
			// 	results = append(results, dirResults...)
			// 	anyProcessed = true
			// }

		default:
			log.Debugf("processing file: %s", path)

			file, err := getFileHandle(ctx, path)
			if err != nil {
				log.Warnf("failed to open file %s: %v", path, err)
				continue
			}
			defer file.Close()

			signature, err := getSignature(
				ctx,
				path,
				config.SignatureBundle.SigValue,
				config.SignatureBundle.PublicKey,
			)
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			res, err := SBOMEvaluation(ctx, file, signature, config, path)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}

			results = append(results, res)
			anyProcessed = true
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
