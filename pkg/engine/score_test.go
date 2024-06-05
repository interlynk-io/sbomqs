package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

type Relationships struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

type CreationInfo struct {
	Creators           []string  `json:"creators"`
	Created            time.Time `json:"created"`
	LicenseListVersion string    `json:"licenseListVersion"`
}

type Package struct {
	SPDXID                  string                  `json:"SPDXID"`
	Name                    string                  `json:"name"`
	VersionInfo             string                  `json:"versionInfo"`
	FilesAnalyzed           bool                    `json:"filesAnalyzed"`
	DataLicense             string                  `json:"dataLicense"`
	LicenseDeclared         string                  `json:"licenseDeclared"`
	LicenseConcluded        string                  `json:"licenseConcluded"`
	DownloadLocation        string                  `json:"downloadLocation"`
	CopyrightText           string                  `json:"copyrightText"`
	Checksums               []Checksums             `json:"checksums"`
	ExternalRefs            []ExternalRef           `json:"externalRefs"`
	PackageVerificationCode PackageVerificationCode `json:"packageVerificationCode"`
	Summary                 string                  `json:"summary"`
	Homepage                string                  `json:"homepage"`
}

type Checksums struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type PackageVerificationCode struct {
	PackageVerificationCodeValue string `json:"packageVerificationCodeValue"`
}

type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type SbomJson struct {
	SPDXID            string          `json:"SPDXID"`
	Name              string          `json:"name"`
	SpdxVersion       string          `json:"spdxVersion"`
	CreationInfo      CreationInfo    `json:"creationInfo"`
	DataLicense       string          `json:"dataLicense"`
	DocumentNamespace string          `json:"documentNamespace"`
	DocumentDescribes []string        `json:"documentDescribes"`
	Packages          []Package       `json:"packages"`
	Relationships     []Relationships `json:"relationships"`
}

var missingAuthorName = SbomJson{
	SPDXID:      "SPDXRef-DOCUMENT",
	Name:        "xyz-0.1.0",
	SpdxVersion: "SPDX-2.2",
	CreationInfo: CreationInfo{
		Creators:           []string{"Organization: Example Inc."},
		Created:            time.Date(2020, 7, 23, 18, 30, 22, 0, time.UTC),
		LicenseListVersion: "3.9",
	},
	DataLicense:       "CC0-1.0",
	DocumentNamespace: "http://spdx.org/spdxdocs/spdx-document-xyz",
	DocumentDescribes: []string{"SPDXRef-Package-xyz"},
	Packages: []Package{
		{
			SPDXID:           "SPDXRef-Package-xyz",
			Name:             "xyz",
			VersionInfo:      "0.1.0",
			FilesAnalyzed:    false,
			LicenseDeclared:  "Apache-2.0 AND curl AND LicenseRef-Proprietary-ExampleInc",
			LicenseConcluded: "NOASSERTION",
			DownloadLocation: "git+ssh://gitlab.example.com:3389/products/xyz.git@b2c358080011af6a366d2512a25a379fbe7b1f78",
			CopyrightText:    "copyright 2004-2020 Example Inc. All Rights Reserved.",
		},
		{
			SPDXID:           "SPDXRef-Package-curl",
			Name:             "curl",
			VersionInfo:      "7.70.0",
			FilesAnalyzed:    false,
			LicenseDeclared:  "curl",
			LicenseConcluded: "NOASSERTION",
			DownloadLocation: "https://github.com/curl/curl/releases/download/curl-7_70_0/curl-7.70.0.tar.gz",
			CopyrightText:    "Copyright (c) 1996 - 2020, Daniel Stenberg, <daniel@haxx.se>, and many contributors, see the THANKS file.",
		},
		{
			SPDXID:           "SPDXRef-Package-openssl",
			Name:             "openssl",
			VersionInfo:      "1.1.1g",
			FilesAnalyzed:    false,
			LicenseDeclared:  "Apache-2.0",
			LicenseConcluded: "NOASSERTION",
			DownloadLocation: "git+ssh://github.com/openssl/openssl.git@e2e09d9fba1187f8d6aafaa34d4172f56f1ffb72",
			CopyrightText:    "copyright 2004-2020 The OpenSSL Project Authors. All Rights Reserved.",
		},
	},
	Relationships: []Relationships{
		{
			SpdxElementID:      "SPDXRef-Package-xyz",
			RelatedSpdxElement: "SPDXRef-Package-curl",
			RelationshipType:   "CONTAINS",
		},
		{
			SpdxElementID:      "SPDXRef-Package-xyz",
			RelatedSpdxElement: "SPDXRef-Package-openssl",
			RelationshipType:   "CONTAINS",
		},
	},
}

func TestProcessFile(t *testing.T) {
	testCases := []struct {
		name        string
		ctx         context.Context
		ep          Params
		expectedErr error
	}{
		{
			name: "happy-path",
			ctx:  context.Background(),
			ep: Params{
				Path: []string{"./sbomqs-spdx-syft.json"},
			},
			expectedErr: nil,
		},
		{
			name: "happy-path-category",
			ctx:  context.Background(),
			ep: Params{
				Path:     []string{"./sbomqs-spdx-syft.json"},
				Category: "NTIA-minimum-elements",
			},
			expectedErr: nil,
		},
		{
			name: "happy-path-basic",
			ctx:  context.Background(),
			ep: Params{
				Path:     []string{"./sbomqs-spdx-syft.json"},
				Category: "NTIA-minimum-elements",
				Basic:    true,
			},
			expectedErr: nil,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := processFile(test.ctx, &test.ep, test.ep.Path[0])
			if !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error (%v), got error (%v)", test.expectedErr, err)
			}
		})
	}
}
