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

package catalog

import "github.com/interlynk-io/sbomqs/pkg/sbom"

// ComprFeatSpec represents feature of comprehenssive categories.
type ComprFeatSpec struct {
	Name        string
	Description string
	Ignore      bool
	Key         ComprFeatKey
	Weight      float64
	Evaluate    ComprFeatEval
}

// ComprFeatEval function represents evaluation of corresponding feature.
type ComprFeatEval func(doc sbom.Document) ComprFeatScore

// ComprFeatScore carries score of a comprehenssive feature
type ComprFeatScore struct {
	Score  float64
	Desc   string // e.g. "235/247 have versions"
	Ignore bool
}
