// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"context"
	"strings"
	"testing"

	spdx_common "github.com/spdx/tools-golang/spdx/common"
	spdx "github.com/spdx/tools-golang/spdx/v2_3"
)

func testSpdxDoc() *spdx.Document {
	return &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    spdx_common.ElementID("DOCUMENT"),
		DocumentName:      "SPDX-Go-Test-document",
		DocumentNamespace: "http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C4401",
		CreationInfo: &spdx.CreationInfo{
			LicenseListVersion: "3.9",
			Creators: []spdx_common.Creator{
				{CreatorType: "Organization", Creator: "Interlynk.io ()"},
				{CreatorType: "Person", Creator: "Ritesh Noronha ()"},
			},
			Created: "2023-02-13T21:52:36+0000",
		},
		Packages: []*spdx.Package{
			{
				PackageName:             "github.com/CycloneDX/cyclonedx-go",
				PackageSPDXIdentifier:   spdx_common.ElementID("go-module-github.com-CycloneDX-cyclonedx-go-49d9f8e76205b17e"),
				PackageVersion:          "v0.0.0-20210810181110-49d9f8e76205",
				PackageDownloadLocation: "NOASSERTION",
				PackageSupplier: &spdx_common.Supplier{
					Supplier: "OWASP",
				},
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Locator: "pkg:golang/github.com/dummy/dummyArrayLib@v2.4.1",
						RefType: spdx_common.TypePackageManagerPURL,
					},
					{
						Locator: "cpe:2:a:golang:go-testlib:v0.0.3:*:*:*:*:*:*:*",
						RefType: spdx_common.TypeSecurityCPE23Type,
					},
				},
			},
			{
				PackageName:             "github.com/inconshreveable/mousetrap",
				PackageSPDXIdentifier:   spdx_common.ElementID("go-module-github.com-inconshreveable-mousetrap-9434bd3d0b12ac21"),
				PackageVersion:          "v1.0.1",
				PackageDownloadLocation: "NOASSERTION",
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Locator: "dummy:golang/github.com/dummy/dummyArrayLib@v2.4.1",
						RefType: spdx_common.TypePackageManagerPURL,
					},
					{
						Locator: "cpe:2.3:a:golang:dummyLib:v3.0.0:*:*:*:*:*:*:*",
						RefType: spdx_common.TypeSecurityCPE23Type,
					},
				},
			},
			{
				PackageName:             "github.com/jessevdk/go-flags",
				PackageSPDXIdentifier:   spdx_common.ElementID("go-module-github.com-jessevdk-go-flags-3f7f1f7f2f1e2e3e"),
				PackageVersion:          "v1.4.0",
				PackageDownloadLocation: "NOASSERTION",
				PackageSupplier: &spdx_common.Supplier{
					Supplier: "",
				},
				PackageExternalReferences: []*spdx.PackageExternalReference{
					{
						Locator: "",
						RefType: spdx_common.TypePackageManagerPURL,
					},
					{
						Locator: "cpe:/a:inkthemes:colorway:3.2.7::~~~wordpress~~",
						RefType: spdx_common.TypeSecurityCPE22Type,
					},
				},
			},
			{
				PackageName:             "github.com/joho/godotenv",
				PackageSPDXIdentifier:   spdx_common.ElementID("go-module-github.com-joho-godotenv-1a0d2d5d1b0e5e6e"),
				PackageVersion:          "v1.3.0",
				PackageDownloadLocation: "NOASSERTION",
				PackageSupplier: &spdx_common.Supplier{
					Supplier: "NOASSERTION",
				},
			},
		},
	}
}

func Test_spdxDoc_addSupplierName(t *testing.T) {
	type fields struct {
		doc     *spdx.Document
		format  FileFormat
		ctx     context.Context
		spec    *spec
		comps   []Component
		authors []Author
		tools   []Tool
		rels    []Relation
		logs    []string
	}
	type args struct {
		index int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{"Supplier name is present", fields{doc: testSpdxDoc()}, args{index: 0}, strings.ToLower("OWASP")},
		{"Supplier section is missing", fields{doc: testSpdxDoc()}, args{index: 1}, ""},
		{"Supplier name is empty", fields{doc: testSpdxDoc()}, args{index: 2}, ""},
		{"Supplier name has noassertion", fields{doc: testSpdxDoc()}, args{index: 3}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxDoc{
				doc:     tt.fields.doc,
				format:  tt.fields.format,
				ctx:     tt.fields.ctx,
				spec:    tt.fields.spec,
				comps:   tt.fields.comps,
				authors: tt.fields.authors,
				tools:   tt.fields.tools,
				rels:    tt.fields.rels,
				logs:    tt.fields.logs,
			}
			if got := s.addSupplierName(tt.args.index); got != tt.want {
				t.Errorf("spdxDoc.addSupplierName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_spdxDoc_purls(t *testing.T) {
	type fields struct {
		doc     *spdx.Document
		format  FileFormat
		ctx     context.Context
		spec    *spec
		comps   []Component
		authors []Author
		tools   []Tool
		rels    []Relation
		logs    []string
	}
	type args struct {
		index int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{"Valid PURL", fields{doc: testSpdxDoc()}, args{index: 0}, 1},
		{"Invalid PURL", fields{doc: testSpdxDoc()}, args{index: 1}, 0},
		{"Invalid PURL", fields{doc: testSpdxDoc()}, args{index: 2}, 0},
		{"No PURL present", fields{doc: testSpdxDoc()}, args{index: 3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxDoc{
				doc:     tt.fields.doc,
				format:  tt.fields.format,
				ctx:     tt.fields.ctx,
				spec:    tt.fields.spec,
				comps:   tt.fields.comps,
				authors: tt.fields.authors,
				tools:   tt.fields.tools,
				rels:    tt.fields.rels,
				logs:    tt.fields.logs,
			}
			if got := s.purls(tt.args.index); len(got) != tt.want {
				t.Errorf("s.purls() = %v, want %v", len(got), tt.want)
			}
		})
	}
}


func Test_spdxDoc_cpes(t *testing.T) {
	type fields struct {
		doc     *spdx.Document
		format  FileFormat
		ctx     context.Context
		spec    *spec
		comps   []Component
		authors []Author
		tools   []Tool
		rels    []Relation
		logs    []string
	}
	type args struct {
		index int
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{"Invalid CPE", fields{doc: testSpdxDoc()}, args{index: 0}, 0},
		{"Valid CPE 2.3", fields{doc: testSpdxDoc()}, args{index: 1}, 1},
		{"Valid CPE 2.2", fields{doc: testSpdxDoc()}, args{index: 2}, 1},
		{"No CPE", fields{doc: testSpdxDoc()}, args{index: 3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &spdxDoc{
				doc:     tt.fields.doc,
				format:  tt.fields.format,
				ctx:     tt.fields.ctx,
				spec:    tt.fields.spec,
				comps:   tt.fields.comps,
				authors: tt.fields.authors,
				tools:   tt.fields.tools,
				rels:    tt.fields.rels,
				logs:    tt.fields.logs,
			}
			s.parse()
			if got := s.cpes(tt.args.index); len(got) != tt.want {
				t.Errorf("s.cpes() = %v, want %v", len(got), tt.want)
			}
		})
	}
}
