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

//counterfeiter:generate . GetSignature

// GetSignature defines the interface for accessing cryptographic signature information in SBOMs
type GetSignature interface {
	// GetAlgorithm returns the signature algorithm (e.g., RS256, ES256)
	GetAlgorithm() string
	// GetKeyID returns the key identifier
	GetKeyID() string
	// GetSigValue returns the cryptographic signature value
	GetSigValue() string
	// GetPublicKey returns the public key used for signature verification
	GetPublicKey() string
	// GetCertificatePath returns the certificate chain path
	GetCertificatePath() []string
	// GetExcludes returns the list of properties excluded from signing
	GetExcludes() []string
}

// Signature represents a concrete implementation of cryptographic signature information
type Signature struct {
	Algorithm       string
	KeyID           string
	SigValue        string
	PublicKey       string
	CertificatePath []string
	Excludes        []string
}

// GetAlgorithm returns the signature algorithm
func (s *Signature) GetAlgorithm() string {
	return s.Algorithm
}

// GetKeyID returns the key identifier
func (s *Signature) GetKeyID() string {
	return s.KeyID
}

// GetSigValue returns the cryptographic signature value
func (s *Signature) GetSigValue() string {
	return s.SigValue
}

// GetPublicKey returns the public key used for signature verification
func (s *Signature) GetPublicKey() string {
	return s.PublicKey
}

// GetCertificatePath returns the certificate chain path
func (s *Signature) GetCertificatePath() []string {
	return s.CertificatePath
}

// GetExcludes returns the list of properties excluded from signing
func (s *Signature) GetExcludes() []string {
	return s.Excludes
}
