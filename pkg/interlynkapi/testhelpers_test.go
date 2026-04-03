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

package interlynkapi

import (
	"fmt"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

const second = time.Second

// makeFakeComponents returns n minimal sbom.Component values (name + version)
// that satisfy sbom.GetComponent without requiring a real parsed SBOM.
func makeFakeComponents(n int) []sbom.GetComponent {
	comps := make([]sbom.GetComponent, n)
	for i := range comps {
		c := sbom.NewComponent()
		c.Name = fmt.Sprintf("comp-%d", i)
		c.Version = "1.0.0"
		comps[i] = c
	}
	return comps
}
