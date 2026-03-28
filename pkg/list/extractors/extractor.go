// Copyright 2026 Interlynk.io
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

// Package extractors provides profile-aware field extractors for the list command.
// Each extractor mirrors the logic of the corresponding scorer profile function
// but returns the actual extracted value instead of a score.
package extractors

import "github.com/interlynk-io/sbomqs/v2/pkg/sbom"

// CompExtractor extracts a feature value from a single component in the context of a document.
// Returns (hasFeature, extractedValue, error).
type CompExtractor func(doc sbom.Document, comp sbom.GetComponent) (bool, string, error)

// DocExtractor extracts a feature value from the SBOM document level.
// Returns (hasFeature, extractedValue, error).
type DocExtractor func(doc sbom.Document) (bool, string, error)
