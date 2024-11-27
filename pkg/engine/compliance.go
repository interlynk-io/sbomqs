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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
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
	signature := ep.Signature
	publicKey := ep.PublicKey

	if signature == "" && publicKey == "" {
		standaloneSBOMFile, signatureRetrieved, publicKeyRetrieved, err := RetrieveSignatureFromSBOM(blob)
		if err != nil {
			log.Fatalf("failed to retrieve signature and public key from embedded sbom: %w", err)
		}
		blob = standaloneSBOMFile
		signature = signatureRetrieved
		publicKey = publicKeyRetrieved
	}
	fmt.Println("Blob: ", blob)
	fmt.Println("Signature: ", signature)
	fmt.Println("PublicKey: ", publicKey)

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      blob,
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
	Signature *Signature             `json:"signature"`
	OtherData map[string]interface{} `json:"-"` // Holds the remaining SBOM data
}

type Signature struct {
	Algorithm string     `json:"algorithm"`
	Value     string     `json:"value"`
	PublicKey *PublicKey `json:"publicKey"`
}

type PublicKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func RetrieveSignatureFromSBOM(sbomFile string) (string, string, string, error) {
	var err error

	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return "", "", "", fmt.Errorf("error reading SBOM file: %w", err)
	}

	var sbom SBOM
	extracted_signature := "extracted_signature.bin"
	extracted_publick_key := "extracted_public_key.pem"

	if err := json.Unmarshal(data, &sbom); err != nil {
		fmt.Println("Error parsing SBOM JSON:", err)
		return "", "", "", fmt.Errorf("error unmarshalling SBOM JSON: %w", err)
	}

	// Extract and print the signature
	if sbom.Signature == nil {
		fmt.Println("signature and public key are not present in the SBOM")
		return sbomFile, "", "", nil
	} else {
		fmt.Println("signature and public key are present in the SBOM")

		signatureValue, err := base64.StdEncoding.DecodeString(sbom.Signature.Value)
		if err != nil {
			return "", "", "", fmt.Errorf("Error decoding signature: %w", err)
		}

		if err := os.WriteFile(extracted_signature, signatureValue, 0o644); err != nil {
			fmt.Println("Error writing signature to file:", err)
		}
		fmt.Println("Signature written to file: extracted_signature.bin")

		// extract the public key modulus and exponent
		modulus, err := base64.StdEncoding.DecodeString(sbom.Signature.PublicKey.N)
		if err != nil {
			return "", "", "", fmt.Errorf("Error decoding public key modulus: %w", err)
		}
		exponent := decodeBase64URLEncodingToInt(sbom.Signature.PublicKey.E)
		if exponent == 0 {
			fmt.Println("Invalid public key exponent.")
		}

		// create the RSA public key
		pubKey := &rsa.PublicKey{
			N: decodeBigInt(modulus),
			E: int(exponent),
		}

		pubKeyPEM := publicKeyToPEM(pubKey)
		if err := os.WriteFile(extracted_publick_key, pubKeyPEM, 0o644); err != nil {
			fmt.Println("Error writing public key to file:", err)
		}

	}

	// remove the "signature" section
	modifiedSBOM, err := sjson.DeleteBytes(data, "signature")
	if err != nil {
		fmt.Println("Error removing signature section:", err)
	}

	var normalizedSBOM bytes.Buffer
	if err := json.Indent(&normalizedSBOM, modifiedSBOM, "", "  "); err != nil {
		fmt.Println("Error normalizing SBOM JSON:", err)
	}

	// save the modified SBOM to a new file without a trailing newline
	standaloneSBOMFile := "standalone_sbom.json"
	if err := os.WriteFile(standaloneSBOMFile, bytes.TrimSuffix(normalizedSBOM.Bytes(), []byte("\n")), 0o644); err != nil {
		return "", "", "", fmt.Errorf("error writing standalone SBOM file: %w", err)
	}

	fmt.Println("Standalone SBOM saved to:", standaloneSBOMFile)
	return standaloneSBOMFile, extracted_signature, extracted_publick_key, nil
}

func decodeBase64URLEncodingToInt(input string) int {
	bytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return 0
	}
	if len(bytes) == 0 {
		return 0
	}
	result := 0
	for _, b := range bytes {
		result = result<<8 + int(b)
	}
	return result
}

func decodeBigInt(input []byte) *big.Int {
	result := new(big.Int)
	result.SetBytes(input)
	return result
}

func publicKeyToPEM(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return nil
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubPEM
}
