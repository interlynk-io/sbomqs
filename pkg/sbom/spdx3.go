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
	"fmt"
	"io"
)

// newSPDX3Doc is a placeholder for SPDX 3.x support
// This will be implemented when spdx-zen library is integrated
func newSPDX3Doc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion) (Document, error) {
	return nil, fmt.Errorf("SPDX 3.x support is not yet implemented")
}