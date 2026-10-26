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

package common

import (
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

func TestIsSupplierEntity(t *testing.T) {
	email := sbom.Contact{Email: "security@example.com"}
	nameOnly := sbom.Contact{Name: "Security Team"}

	for _, tt := range []struct {
		name     string
		supplier sbom.Supplier
		want     bool
	}{
		{"email only", sbom.Supplier{Contacts: []sbom.Contact{email}}, true},
		{"name only, no contacts", sbom.Supplier{Name: "Acme Inc"}, true},
		{"no name, no contacts", sbom.Supplier{}, false},
		{"contact without an email", sbom.Supplier{Contacts: []sbom.Contact{nameOnly}}, false},
		{"email on the first of two contacts", sbom.Supplier{Contacts: []sbom.Contact{email, nameOnly}}, true},
		{"email on the last of two contacts", sbom.Supplier{Contacts: []sbom.Contact{nameOnly, email}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSupplierEntity(tt.supplier); got != tt.want {
				t.Errorf("IsSupplierEntity() = %v, want %v", got, tt.want)
			}
		})
	}
}
