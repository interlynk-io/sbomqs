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

package sbom

import (
	"context"
	"strings"
	"testing"
)

func TestCdxDocSignatureParsing(t *testing.T) {
	tests := []struct {
		name             string
		json             string
		wantAlgorithm    string
		wantKeyID        string
		wantHasSignature bool
		wantHasPublicKey bool
	}{
		{
			name: "Single signer with RSA key",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"signature": {
					"algorithm": "RS256",
					"keyId": "test-key-123",
					"publicKey": {
						"kty": "RSA",
						"n": "AMjlMZS_czb5d3cQ",
						"e": "AQAB"
					},
					"value": "dGVzdHNpZ25hdHVyZQ=="
				},
				"components": []
			}`,
			wantAlgorithm:    "RS256",
			wantKeyID:        "test-key-123",
			wantHasSignature: true,
			wantHasPublicKey: true,
		},
		{
			name: "Single signer with EC key",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"signature": {
					"algorithm": "ES256",
					"publicKey": {
						"kty": "EC",
						"crv": "P-256",
						"x": "AMjlMZS_czb5d3cQ",
						"y": "AQAB"
					},
					"value": "dGVzdHNpZ25hdHVyZQ=="
				},
				"components": []
			}`,
			wantAlgorithm:    "ES256",
			wantHasSignature: true,
			wantHasPublicKey: true,
		},
		{
			name: "Multiple signers",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"signature": {
					"signers": [
						{
							"algorithm": "RS256",
							"keyId": "signer1",
							"value": "sig1"
						},
						{
							"algorithm": "ES256",
							"keyId": "signer2",
							"value": "sig2"
						}
					]
				},
				"components": []
			}`,
			wantAlgorithm:    "RS256", // First signer
			wantKeyID:        "signer1",
			wantHasSignature: true,
		},
		{
			name: "Signature with certificate path",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"signature": {
					"algorithm": "RS256",
					"certificatePath": ["cert1.pem", "cert2.pem"],
					"value": "dGVzdHNpZ25hdHVyZQ=="
				},
				"components": []
			}`,
			wantAlgorithm:    "RS256",
			wantHasSignature: true,
		},
		{
			name: "Signature with excludes",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"signature": {
					"algorithm": "RS256",
					"excludes": ["timestamp", "serialNumber"],
					"value": "dGVzdHNpZ25hdHVyZQ=="
				},
				"components": []
			}`,
			wantAlgorithm:    "RS256",
			wantHasSignature: true,
		},
		{
			name: "No signature",
			json: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.6",
				"components": []
			}`,
			wantHasSignature: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			reader := strings.NewReader(tt.json)

			doc, err := newCDXDoc(ctx, reader, FileFormatJSON, Signature{})
			if err != nil {
				t.Fatalf("Failed to parse CDX document: %v", err)
			}

			cdxDoc, ok := doc.(*CdxDoc)
			if !ok {
				t.Fatalf("Document is not a CdxDoc")
			}

			sig := cdxDoc.Signature()

			if tt.wantHasSignature && sig == nil {
				t.Error("Expected signature but got nil")
				return
			}

			if !tt.wantHasSignature && sig != nil {
				t.Error("Expected no signature but got one")
				return
			}

			if !tt.wantHasSignature {
				return // No more checks needed
			}

			if got := sig.GetAlgorithm(); got != tt.wantAlgorithm {
				t.Errorf("Algorithm = %v, want %v", got, tt.wantAlgorithm)
			}

			if tt.wantKeyID != "" {
				if got := sig.GetKeyID(); got != tt.wantKeyID {
					t.Errorf("KeyID = %v, want %v", got, tt.wantKeyID)
				}
			}

			if tt.wantHasPublicKey {
				if got := sig.GetPublicKey(); got == "" {
					t.Error("Expected public key but got empty string")
				}
			}

			// Check that signature value is present
			if got := sig.GetSigValue(); got == "" && tt.wantHasSignature {
				t.Error("Expected signature value but got empty string")
			}
		})
	}
}

func TestCdxDocSignatureWithCertificatePath(t *testing.T) {
	json := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"signature": {
			"algorithm": "RS256",
			"certificatePath": ["root.pem", "intermediate.pem", "leaf.pem"],
			"value": "dGVzdHNpZ25hdHVyZQ=="
		},
		"components": []
	}`

	ctx := context.Background()
	reader := strings.NewReader(json)

	doc, err := newCDXDoc(ctx, reader, FileFormatJSON, Signature{})
	if err != nil {
		t.Fatalf("Failed to parse CDX document: %v", err)
	}

	sig := doc.Signature()
	if sig == nil {
		t.Fatal("Expected signature but got nil")
	}

	certPath := sig.GetCertificatePath()
	if len(certPath) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(certPath))
	}

	expectedCerts := []string{"root.pem", "intermediate.pem", "leaf.pem"}
	for i, cert := range certPath {
		if cert != expectedCerts[i] {
			t.Errorf("Certificate[%d] = %v, want %v", i, cert, expectedCerts[i])
		}
	}
}

func TestCdxDocSignatureWithExcludes(t *testing.T) {
	json := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"signature": {
			"algorithm": "RS256",
			"excludes": ["timestamp", "serialNumber", "metadata.timestamp"],
			"value": "dGVzdHNpZ25hdHVyZQ=="
		},
		"components": []
	}`

	ctx := context.Background()
	reader := strings.NewReader(json)

	doc, err := newCDXDoc(ctx, reader, FileFormatJSON, Signature{})
	if err != nil {
		t.Fatalf("Failed to parse CDX document: %v", err)
	}

	sig := doc.Signature()
	if sig == nil {
		t.Fatal("Expected signature but got nil")
	}

	excludes := sig.GetExcludes()
	if len(excludes) != 3 {
		t.Errorf("Expected 3 excludes, got %d", len(excludes))
	}

	expectedExcludes := []string{"timestamp", "serialNumber", "metadata.timestamp"}
	for i, exclude := range excludes {
		if exclude != expectedExcludes[i] {
			t.Errorf("Exclude[%d] = %v, want %v", i, exclude, expectedExcludes[i])
		}
	}
}
