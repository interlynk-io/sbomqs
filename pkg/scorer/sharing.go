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
// limitations under the License.

package scorer

import (
	"fmt"

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

func sharableLicenseCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	lics := d.Spec().GetLicenses()

	freeLics := lo.CountBy(lics, func(l licenses.License) bool {
		return l.FreeAnyUse()
	})

	if len(lics) > 0 && freeLics == len(lics) {
		s.setScore(10.0)
	}

	s.setDesc(fmt.Sprintf("doc has a sharable license free %d :: of %d", freeLics, len(lics)))
	return *s
}
