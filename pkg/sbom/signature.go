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
	// GetSigValue returns the cryptographic signature value
	GetSigValue() string
	// GetPublicKey returns the public key used for signature verification
	GetPublicKey() string
	// GetBlob returns the signature blob or additional signature data
	GetBlob() string
}

// Signature represents a concrete implementation of cryptographic signature information
type Signature struct {
	SigValue  string
	PublicKey string
	Blob      string
}

// GetSigValue returns the cryptographic signature value
func (s *Signature) GetSigValue() string {
	return s.SigValue
}

// GetPublicKey returns the public key used for signature verification
func (s *Signature) GetPublicKey() string {
	return s.PublicKey
}

// GetBlob returns the signature blob or additional signature data
func (s *Signature) GetBlob() string {
	return s.Blob
}
