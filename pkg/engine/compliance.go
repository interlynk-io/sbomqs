// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/compliance"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/spf13/afero"
	"github.com/tidwall/sjson"
)

func ComplianceRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ComplianceRun()")

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	log.Debugf("Config: %+v", ep)

	doc, err := getSbomDocument(ctx, ep)
	if err != nil {
		log.Debugf("getSbomDocument failed for file :%s\n", ep.Path[0])
		fmt.Printf("failed to get sbom document for %s\n", ep.Path[0])
		return err
	}

	var reportType string

	switch {
	case ep.Bsi:
		reportType = "BSI"
	case ep.BsiV2:
		reportType = "BSI-V2"
	case ep.Oct:
		reportType = "OCT"
	case ep.Fsct:
		reportType = "FSCT"
	default:
		reportType = "NTIA"
	}

	var outFormat string

	switch {
	case ep.Basic:
		outFormat = "basic"
	case ep.JSON:
		outFormat = "json"
	default:
		outFormat = "detailed"
	}

	coloredOutput := ep.Color

	err = compliance.ComplianceResult(ctx, *doc, reportType, ep.Path[0], outFormat, coloredOutput)
	if err != nil {
		log.Debugf("compliance.ComplianceResult failed for file :%s\n", ep.Path[0])
		fmt.Printf("failed to get compliance result for %s\n", ep.Path[0])
		return err
	}

	log.Debugf("Compliance Report: %s\n", ep.Path[0])
	return nil
}

func getSbomDocument(ctx context.Context, ep *Params) (*sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debugf("engine.getSbomDocument()")

	path := ep.Path[0]

	blob := ep.Path[0]
	fmt.Println("Blob: ", blob)
	signature := ep.Signature
	fmt.Println("Signature: ", signature)
	publicKey := ep.PublicKey
	fmt.Println("PublicKey: ", publicKey)

	standaloneSBOMFile, err := CheckSbomHasSignature(blob)
	if err != nil {
		log.Fatalf("failed to get standalone SBOM: %w", err)
	}

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      standaloneSBOMFile,
	}
	var doc sbom.Document

	if IsURL(path) {
		log.Debugf("Processing Git URL path :%s\n", path)
		url, sbomFilePath := path, path
		var err error

		if IsGit(url) {
			sbomFilePath, url, err = handleURL(path)
			if err != nil {
				log.Fatal("failed to get sbomFilePath, rawURL: %w", err)
			}
		}
		fs := afero.NewMemMapFs()

		file, err := fs.Create(sbomFilePath)
		if err != nil {
			return nil, err
		}

		f, err := ProcessURL(url, file)
		if err != nil {
			return nil, err
		}

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Fatalf("failed to parse SBOM document: %w", err)
		}
	} else {
		if _, err := os.Stat(path); err != nil {
			log.Debugf("os.Stat failed for file :%s\n", path)
			fmt.Printf("failed to stat %s\n", path)
			return nil, err
		}

		f, err := os.Open(path)
		if err != nil {
			log.Debugf("os.Open failed for file :%s\n", path)
			fmt.Printf("failed to open %s\n", path)
			return nil, err
		}
		defer f.Close()

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Debugf("failed to create sbom document for  :%s\n", path)
			log.Debugf("%s\n", err)
			fmt.Printf("failed to parse %s : %s\n", path, err)
			return nil, err
		}
	}

	return &doc, nil
}

type SBOM struct {
	Signature map[string]interface{} `json:"signature"`
	OtherData map[string]interface{} `json:"-"` // Holds the remaining SBOM data
}

func CheckSbomHasSignature(sbomFile string) (string, error) {
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return "", fmt.Errorf("error reading SBOM file: %w", err)
	}

	var sbom SBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		fmt.Println("Error parsing SBOM JSON:", err)
		return "", fmt.Errorf("error unmarshalling SBOM JSON: %w", err)
	}

	// Extract and print the signature
	if sbom.Signature == nil {
		fmt.Println("No signature found in SBOM.")
		return sbomFile, nil
	}

	// Remove the "signature" section
	modifiedSBOM, err := sjson.DeleteBytes(data, "signature")
	if err != nil {
		fmt.Println("Error removing signature section:", err)
	}

	// Normalize JSON for consistency
	var normalizedSBOM bytes.Buffer
	if err := json.Indent(&normalizedSBOM, modifiedSBOM, "", "  "); err != nil {
		fmt.Println("Error normalizing SBOM JSON:", err)
	}

	// Save the modified SBOM to a new file without a trailing newline
	standaloneSBOMFile := "standalone_sbom.json"
	if err := os.WriteFile(standaloneSBOMFile, bytes.TrimSuffix(normalizedSBOM.Bytes(), []byte("\n")), 0o644); err != nil {
		return "", fmt.Errorf("error writing standalone SBOM file: %w", err)
	}

	fmt.Println("Standalone SBOM saved to:", standaloneSBOMFile)
	return standaloneSBOMFile, nil
}
