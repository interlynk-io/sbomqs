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

package licenses

import (
	"testing"
)

func TestLookupExpression_AllDeprecatedLicenses(t *testing.T) {

	testcases := []struct {
		exp             string
		wantName        string
		wantDeprecated  bool
		wantRestrictive bool
	}{
		{exp: "AGPL-1.0", wantName: "AGPL-1.0", wantDeprecated: true, wantRestrictive: true},
		{exp: "AGPL-3.0", wantName: "AGPL-3.0", wantDeprecated: true, wantRestrictive: true},

		{exp: "BSD-2-Clause-FreeBSD", wantName: "BSD-2-Clause-FreeBSD", wantDeprecated: true, wantRestrictive: false},
		{exp: "BSD-2-Clause-NetBSD", wantName: "BSD-2-Clause-NetBSD", wantDeprecated: true, wantRestrictive: false},

		{exp: "bzip2-1.0.5", wantName: "bzip2-1.0.5", wantDeprecated: true, wantRestrictive: false},
		{exp: "eCos-2.0", wantName: "eCos-2.0", wantDeprecated: true, wantRestrictive: true},

		{exp: "GFDL-1.1", wantName: "GFDL-1.1", wantDeprecated: true, wantRestrictive: true},
		{exp: "GFDL-1.2", wantName: "GFDL-1.2", wantDeprecated: true, wantRestrictive: true},
		{exp: "GFDL-1.3", wantName: "GFDL-1.3", wantDeprecated: true, wantRestrictive: true},

		{exp: "GPL-1.0", wantName: "GPL-1.0", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-1.0+", wantName: "GPL-1.0+", wantDeprecated: true, wantRestrictive: true},

		{exp: "GPL-2.0", wantName: "GPL-2.0", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-2.0+", wantName: "GPL-2.0+", wantDeprecated: true, wantRestrictive: true},

		{exp: "GPL-2.0-with-autoconf-exception", wantName: "GPL-2.0-with-autoconf-exception", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-2.0-with-bison-exception", wantName: "GPL-2.0-with-bison-exception", wantDeprecated: true, wantRestrictive: false},
		{exp: "GPL-2.0-with-classpath-exception", wantName: "GPL-2.0-with-classpath-exception", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-2.0-with-font-exception", wantName: "GPL-2.0-with-font-exception", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-2.0-with-GCC-exception", wantName: "GPL-2.0-with-GCC-exception", wantDeprecated: true, wantRestrictive: true},

		{exp: "GPL-3.0+", wantName: "GPL-3.0+", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-3.0-with-autoconf-exception", wantName: "GPL-3.0-with-autoconf-exception", wantDeprecated: true, wantRestrictive: true},
		{exp: "GPL-3.0-with-GCC-exception", wantName: "GPL-3.0-with-GCC-exception", wantDeprecated: true, wantRestrictive: true},

		{exp: "LGPL-2.0", wantName: "LGPL-2.0", wantDeprecated: true, wantRestrictive: true},
		{exp: "LGPL-2.0+", wantName: "LGPL-2.0+", wantDeprecated: true, wantRestrictive: true},

		{exp: "LGPL-2.1", wantName: "LGPL-2.1", wantDeprecated: true, wantRestrictive: true},
		{exp: "LGPL-2.1+", wantName: "LGPL-2.1+", wantDeprecated: true, wantRestrictive: true},

		{exp: "LGPL-3.0", wantName: "LGPL-3.0", wantDeprecated: true, wantRestrictive: true},
		{exp: "LGPL-3.0+", wantName: "LGPL-3.0+", wantDeprecated: true, wantRestrictive: true},

		{exp: "Net-SNMP", wantName: "Net-SNMP", wantDeprecated: true, wantRestrictive: false},
		{exp: "Nunit", wantName: "Nunit", wantDeprecated: true, wantRestrictive: false},
		{exp: "StandardML-NJ", wantName: "StandardML-NJ", wantDeprecated: true, wantRestrictive: false},
		{exp: "wxWindows", wantName: "wxWindows", wantDeprecated: true, wantRestrictive: true},
	}

	for _, test := range testcases {
		t.Run(test.exp, func(t *testing.T) {
			lics := LookupExpression(test.exp, nil)

			if len(lics) == 0 {
				t.Fatalf("expected license for %s, got none", test.exp)
			}

			lic := lics[0]

			if lic.ShortID() != test.wantName {
				t.Fatalf(
					"expected license ID %s, got %s",
					test.wantName,
					lic.ShortID(),
				)
			}

			if lic.Deprecated() != test.wantDeprecated {
				t.Fatalf(
					"expected deprecated=%v for %s, got %v",
					test.wantDeprecated,
					test.exp,
					lic.Deprecated(),
				)
			}

			if lic.Restrictive() != test.wantRestrictive {
				t.Fatalf(
					"expected restrictive=%v for %s, got %v",
					test.wantRestrictive,
					test.exp,
					lic.Restrictive(),
				)
			}
		})
	}
}

func TestLookupExpression_RestrictiveLicenses(t *testing.T) {
	testcases := []struct {
		exp             string
		wantName        string
		wantRestrictive bool
	}{
		// Strong copyleft
		{exp: "GPL-2.0-only", wantName: "GPL-2.0-only", wantRestrictive: true},
		{exp: "GPL-3.0-only", wantName: "GPL-3.0-only", wantRestrictive: true},
		{exp: "AGPL-3.0-only", wantName: "AGPL-3.0-only", wantRestrictive: true},

		// Weak / limited copyleft
		{exp: "LGPL-2.1-only", wantName: "LGPL-2.1-only", wantRestrictive: true},
		{exp: "LGPL-3.0-only", wantName: "LGPL-3.0-only", wantRestrictive: true},
		{exp: "EPL-2.0", wantName: "EPL-2.0", wantRestrictive: true},
	}

	for _, test := range testcases {
		t.Run(test.exp, func(t *testing.T) {
			lics := LookupExpression(test.exp, nil)

			if len(lics) == 0 {
				t.Fatalf("expected license for %s, got none", test.exp)
			}

			lic := lics[0]

			if lic.ShortID() != test.wantName {
				t.Fatalf(
					"expected license ID %s, got %s",
					test.wantName,
					lic.ShortID(),
				)
			}

			if lic.Restrictive() != test.wantRestrictive {
				t.Fatalf(
					"expected restrictive=%v for %s, got %v",
					test.wantRestrictive,
					test.exp,
					lic.Restrictive(),
				)
			}
		})
	}
}

func TestLookupExpression_PermissiveLicenses(t *testing.T) {
	testcases := []struct {
		exp             string
		wantName        string
		wantRestrictive bool
	}{
		{exp: "Apache-2.0", wantName: "Apache-2.0", wantRestrictive: false},
		{exp: "MIT", wantName: "MIT", wantRestrictive: false},
		{exp: "BSD-3-Clause", wantName: "BSD-3-Clause", wantRestrictive: false},
		{exp: "ISC", wantName: "ISC", wantRestrictive: false},
		{exp: "BSL-1.0", wantName: "BSL-1.0", wantRestrictive: false},
		{exp: "Zlib", wantName: "Zlib", wantRestrictive: false},
	}

	for _, test := range testcases {
		t.Run(test.exp, func(t *testing.T) {
			lics := LookupExpression(test.exp, nil)

			if len(lics) == 0 {
				t.Fatalf("expected license for %s, got none", test.exp)
			}

			lic := lics[0]

			if lic.ShortID() != test.wantName {
				t.Fatalf(
					"expected license ID %s, got %s",
					test.wantName,
					lic.ShortID(),
				)
			}

			if lic.Restrictive() != test.wantRestrictive {
				t.Fatalf(
					"expected restrictive=%v for %s, got %v",
					test.wantRestrictive,
					test.exp,
					lic.Restrictive(),
				)
			}
		})
	}
}

func TestLookupExpression_CustomLicenses(t *testing.T) {
	customLicenses := []License{CreateCustomLicense("LicenseRef-Internal-Company-License", "LicenseRef-Internal-Company-License")}

	testcases := []struct {
		exp             string
		wantName        string
		wantRestrictive bool
	}{
		{
			exp:             "LicenseRef-Internal-Company-License",
			wantName:        "LicenseRef-Internal-Company-License",
			wantRestrictive: false,
		},
	}

	for _, test := range testcases {
		t.Run(test.exp, func(t *testing.T) {
			lics := LookupExpression(test.exp, customLicenses)

			if len(lics) == 0 {
				t.Fatalf("expected license for %s, got none", test.exp)
			}

			lic := lics[0]

			if lic.ShortID() != test.wantName {
				t.Fatalf(
					"expected license ID %s, got %s",
					test.wantName,
					lic.ShortID(),
				)
			}

			if lic.Restrictive() != test.wantRestrictive {
				t.Fatalf(
					"didn't expected restrictive=%v for %s, got %v",
					test.wantRestrictive,
					test.exp,
					lic.Restrictive(),
				)
			}
		})
	}
}
