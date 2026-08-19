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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A signature block with no publicKey. CycloneDX JSF permits this: the
// verification material can be referenced by certPath/keyId or supplied out of
// band. This is the shape of samples/sbom.cdx.signed.json.
const sbomSignatureWithoutPublicKey = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [],
  "signature": {
    "algorithm": "ES256",
    "value": "MEUCIG9lOD40k/frCtBGY6bVXincsOoXUz83uxHU3pdvdY2XAiEApU6pHZDzKym1msnAOpTZNPBwa+wLriwGMZIY1ScOzDs="
  }
}`

const sbomSignatureWithPublicKey = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [],
  "signature": {
    "algorithm": "RS256",
    "value": "c2lnbmF0dXJlLXZhbHVl",
    "publicKey": {
      "kty": "RSA",
      "n": "sMuFYqvJ8n0aQqDCZTa1lTNKQ1ZKBhLOF2sVYt1ETyU=",
      "e": "AQAB"
    }
  }
}`

const sbomWithoutSignature = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": []
}`

func writeSBOM(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

// Regression test for the nil pointer dereference on Signature.PublicKey.
// Before the guard this panicked with SIGSEGV rather than returning.
func TestRetrieveSignatureFromSBOM_SignatureWithoutPublicKey(t *testing.T) {
	path := writeSBOM(t, sbomSignatureWithoutPublicKey)

	standalone, signature, publicKey, err := RetrieveSignatureFromSBOM(context.Background(), path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer RemoveSignatureArtifacts(standalone, signature, publicKey)

	if publicKey != "" {
		t.Fatalf("expected no public key path, got %q", publicKey)
	}

	if signature == "" {
		t.Fatal("expected the signature to still be extracted")
	}

	if _, err := os.Stat(signature); err != nil {
		t.Fatalf("expected signature artifact at %s: %v", signature, err)
	}

	if _, err := os.Stat(standalone); err != nil {
		t.Fatalf("expected standalone SBOM at %s: %v", standalone, err)
	}
}

func TestRetrieveSignatureFromSBOM_SignatureWithPublicKey(t *testing.T) {
	path := writeSBOM(t, sbomSignatureWithPublicKey)

	standalone, signature, publicKey, err := RetrieveSignatureFromSBOM(context.Background(), path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer RemoveSignatureArtifacts(standalone, signature, publicKey)

	for name, artifact := range map[string]string{
		"standalone SBOM": standalone,
		"signature":       signature,
		"public key":      publicKey,
	} {
		if artifact == "" {
			t.Fatalf("expected a %s path", name)
		}
		if _, err := os.Stat(artifact); err != nil {
			t.Fatalf("expected %s artifact at %s: %v", name, artifact, err)
		}
	}

	// The standalone copy is the document with the signature section removed.
	data, err := os.ReadFile(standalone)
	if err != nil {
		t.Fatalf("failed to read standalone SBOM: %v", err)
	}
	if strings.Contains(string(data), "\"signature\"") {
		t.Fatal("expected the signature section to be stripped")
	}
}

func TestRetrieveSignatureFromSBOM_NoSignature(t *testing.T) {
	path := writeSBOM(t, sbomWithoutSignature)

	standalone, signature, publicKey, err := RetrieveSignatureFromSBOM(context.Background(), path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if standalone != path {
		t.Fatalf("expected the original path back, got %q", standalone)
	}

	if signature != "" || publicKey != "" {
		t.Fatalf("expected no artifacts, got signature=%q publicKey=%q", signature, publicKey)
	}
}

// Artifacts must never land next to the caller's working directory.
func TestRetrieveSignatureFromSBOM_DoesNotWriteToWorkingDirectory(t *testing.T) {
	path := writeSBOM(t, sbomSignatureWithPublicKey)

	standalone, signature, publicKey, err := RetrieveSignatureFromSBOM(context.Background(), path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer RemoveSignatureArtifacts(standalone, signature, publicKey)

	for _, artifact := range []string{standalone, signature, publicKey} {
		if !filepath.IsAbs(artifact) {
			t.Fatalf("expected an absolute temp path, got %q", artifact)
		}
		if !strings.HasPrefix(filepath.Base(filepath.Dir(artifact)), "sbomqs-signature-") {
			t.Fatalf("expected %q to live in a sbomqs signature temp dir", artifact)
		}
	}

	for _, leaked := range []string{"extracted_signature.bin", "extracted_public_key.pem", "standalone_sbom.json"} {
		if _, err := os.Stat(leaked); err == nil {
			t.Fatalf("%s was written to the working directory", leaked)
		}
	}
}

func TestRemoveSignatureArtifacts_RemovesFilesAndDir(t *testing.T) {
	path := writeSBOM(t, sbomSignatureWithPublicKey)

	standalone, signature, publicKey, err := RetrieveSignatureFromSBOM(context.Background(), path)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	dir := filepath.Dir(standalone)

	RemoveSignatureArtifacts(standalone, signature, publicKey)

	for _, artifact := range []string{standalone, signature, publicKey} {
		if _, err := os.Stat(artifact); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed", artifact)
		}
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected temp dir %s to be pruned", dir)
	}
}

// The same struct field carries a raw signature value on the CycloneDX parse
// path, so cleanup must ignore anything that is not one of our artifacts.
func TestRemoveSignatureArtifacts_IgnoresForeignPaths(t *testing.T) {
	dir := t.TempDir()
	bystander := filepath.Join(dir, "important.json")
	if err := os.WriteFile(bystander, []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	RemoveSignatureArtifacts("", bystander, "MEUCIG9lOD40k/frCtBGY6bVXincsOoXUz83uxHU3pdvdY2X")

	if _, err := os.Stat(bystander); err != nil {
		t.Fatalf("expected %s to survive cleanup: %v", bystander, err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected %s to survive cleanup: %v", dir, err)
	}
}
