// Copyright 2025 Interlynk.io
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

package common

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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/tidwall/sjson"
)

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

func RetrieveSignatureFromSBOM(ctx context.Context, sbomFile string) (string, string, string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("common.RetrieveSignatureFromSBOM()")
	var err error

	// #nosec G304 -- User-provided paths are expected for CLI tool
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		log.Debug("error reading SBOM file: %w", err)
		return "", "", "", fmt.Errorf("error reading SBOM file: %w", err)
	}

	var sbom SBOM

	//nolint
	extracted_signature := "extracted_signature.bin"

	//nolint
	extracted_publick_key := "extracted_public_key.pem"

	if err := json.Unmarshal(data, &sbom); err != nil {
		log.Debug("Error parsing SBOM JSON: %w", err)
		return "", "", "", fmt.Errorf("error unmarshalling SBOM JSON: %w", err)
	}

	if sbom.Signature == nil {
		log.Debug("signature and public key are not embedded in the SBOM")
		return sbomFile, "", "", nil
	}
	log.Debug("signature and public key are present in the SBOM")

	signatureValue, err := base64.StdEncoding.DecodeString(sbom.Signature.Value)
	if err != nil {
		log.Debug("error decoding signature: %w", err)
		return "", "", "", fmt.Errorf("error decoding signature: %w", err)
	}

	if err := os.WriteFile(extracted_signature, signatureValue, 0o600); err != nil {
		log.Debug("Error writing signature to file:", err)
	}
	log.Debug("Signature written to file: extracted_signature.bin")

	// extract the public key modulus and exponent
	modulus, err := base64.StdEncoding.DecodeString(sbom.Signature.PublicKey.N)
	if err != nil {
		return "", "", "", fmt.Errorf("error decoding public key modulus: %w", err)
	}
	exponent := DecodeBase64URLEncodingToInt(sbom.Signature.PublicKey.E)
	if exponent == 0 {
		log.Debug("Invalid public key exponent.")
	}

	// create the RSA public key
	pubKey := &rsa.PublicKey{
		N: DecodeBigInt(modulus),
		E: exponent,
	}

	pubKeyPEM := PublicKeyToPEM(pubKey)
	if err := os.WriteFile(extracted_publick_key, pubKeyPEM, 0o600); err != nil {
		log.Debug("error writing public key to file: %w", err)
	}

	// remove the "signature" section
	modifiedSBOM, err := sjson.DeleteBytes(data, "signature")
	if err != nil {
		log.Debug("Error removing signature section: %w", err)
	}

	var normalizedSBOM bytes.Buffer
	if err := json.Indent(&normalizedSBOM, modifiedSBOM, "", "  "); err != nil {
		log.Debug("Error normalizing SBOM JSON: %w", err)
	}

	// save the modified SBOM to a new file without a trailing newline
	standaloneSBOMFile := "standalone_sbom.json"
	if err := os.WriteFile(standaloneSBOMFile, bytes.TrimSuffix(normalizedSBOM.Bytes(), []byte("\n")), 0o600); err != nil {
		return "", "", "", fmt.Errorf("error writing standalone SBOM file: %w", err)
	}

	log.Debug("Standalone SBOM saved to:", standaloneSBOMFile)
	return standaloneSBOMFile, extracted_signature, extracted_publick_key, nil
}

func DecodeBase64URLEncodingToInt(input string) int {
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

func DecodeBigInt(input []byte) *big.Int {
	result := new(big.Int)
	result.SetBytes(input)
	return result
}

func PublicKeyToPEM(pub *rsa.PublicKey) []byte {
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

func GetSignatureBundle(ctx context.Context, sbomFile, signature, publicKey string) (string, string, string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("common.GetSignatureBundle()")

	// detect SBOM format for signature handling
	format, err := detectSBOMFormatDirectlyFromSBOMFile(ctx, sbomFile)
	if err != nil {
		log.Debugf("failed to detect SBOM format: %w", err)
		return "", "", "", fmt.Errorf("cannot determine SBOM format for %s: %w", sbomFile, err)
	}

	// handle signature extraction based on format
	if format == "cyclonedx" {
		log.Debug("CycloneDX SBOM detected, attempting to retrieve signature and public key from embedded SBOM")
		standaloneSBOMFile, signatureRetrieved, publicKeyRetrieved, err := RetrieveSignatureFromSBOM(ctx, sbomFile)
		if err != nil {
			log.Debug("failed to retrieve signature and public key from embedded sbom: %w", err)
		}
		return standaloneSBOMFile, signatureRetrieved, publicKeyRetrieved, nil
	} else if format == "spdx" {
		return sbomFile, signature, publicKey, nil
	}
	log.Debugf("Unknown SBOM format: %s", format)

	return "", "", "", nil
}

// detectSBOMFormat attempts to determine if the SBOM is SPDX or CycloneDX by inspecting the file
func detectSBOMFormatDirectlyFromSBOMFile(ctx context.Context, path string) (string, error) {
	log := logger.FromContext(ctx)
	var content []byte
	var err error

	// #nosec G304 -- User-provided paths are expected for CLI tool
	content, err = os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}

	// check for key fields:
	contentStr := strings.ToLower(string(content))
	if strings.Contains(contentStr, `"bomformat": "cyclonedx"`) || strings.Contains(contentStr, `"specversion"`) {
		log.Debugf("Detected CycloneDX SBOM")
		return "cyclonedx", nil
	}
	if strings.Contains(contentStr, "spdxversion") || strings.Contains(contentStr, "spdxid") {
		log.Debugf("Detected SPDX SBOM")
		return "spdx", nil
	}

	return "", nil
}
