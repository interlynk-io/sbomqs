// Copyright 2023 Interlynk.io
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
// limitations under the License

package scorer

import (
	"context"
	"os"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// test scenario for restricted license score
func TestCompWithRestrictedLicensesScore(t *testing.T) {
	ctx := context.Background()
	var tests = []struct {
		name      string
		inputPath string
		want      float64
	}{
		{"With Restricted File", "../../samples/julia.spdx.json", float64(8.823529411764707)},
		{"Without Restricted File", "../../samples/sbomqs.syft-spdx.json", float64(10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputPath)
			if err != nil {
				t.Errorf("os.Open failed for file :%s\n", tt.inputPath)
				return
			}
			defer f.Close()
			doc, _ := sbom.NewSBOMDocument(ctx, f)
			score := compWithRestrictedLicensesScore(doc)
			if score.score != tt.want {
				t.Errorf("got %f, want %f", score.score, tt.want)
			}
		})
	}

}

