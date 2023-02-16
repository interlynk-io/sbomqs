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

package sbom

import (
	"strings"
	"testing"

	cydx "github.com/CycloneDX/cyclonedx-go"
)

func cdxBOM() *cydx.BOM {
	m := cydx.Metadata{
		Component: &cydx.Component{
			BOMRef:  "pkg:golang/interlynk-io/sbomqs@v0.0.1",
			Type:    cydx.ComponentTypeApplication,
			Name:    "SBOMQS application",
			Version: "v0.0.1",
		},
	}

	comps := []cydx.Component{
		{
			BOMRef:     "pkg:golang/github.com/interlynk-io/go-testlib@v0.0.3",
			Type:       cydx.ComponentTypeLibrary,
			Author:     "Interlynk.io",
			Name:       "go-testlib",
			Version:    "v0.0.3",
			PackageURL: "pkg:golang/github.com/interlynk-io/go-testlib@v0.0.3",
		},
		{
			BOMRef:     "pkg:golang/github.com/dummy/dummyLib@v3.0.0",
			Type:       cydx.ComponentTypeLibrary,
			Author:     "Dummy",
			Name:       "dummyLib",
			Version:    "v3.0.0",
			PackageURL: "pkg:golang/github.com/dummy/dummyLib@v3.0.0",
			Supplier: &cydx.OrganizationalEntity{
				Name: "Dummy",
			},
		},
		{
			BOMRef:     "pkg:golang/github.com/dummy/dummyArrayLib@v2.4.1",
			Type:       cydx.ComponentTypeLibrary,
			Author:     "Dummy",
			Name:       "dummyArrayLib",
			Version:    "v2.4.1",
			PackageURL: "pkg:golang/github.com/dummy/dummyArrayLib@v2.4.1",
			Supplier: &cydx.OrganizationalEntity{
				Name: "",
			},
		},
	}
	bom := cydx.NewBOM()
	bom.Metadata = &m
	bom.Components = &comps

	return bom
}

func Test_cdxDoc_addSupplierName(t *testing.T) {
	type fields struct {
		doc     *cydx.BOM
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
		{"Supplier name is found", fields{doc: cdxBOM()}, args{index: 1}, strings.ToLower("Dummy")},
		{"Supplier section is not found", fields{doc: cdxBOM()}, args{index: 0}, ""},
		{"Supplier name is blank", fields{doc: cdxBOM()}, args{index: 2}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cdxDoc{
				doc:     tt.fields.doc,
				spec:    tt.fields.spec,
				comps:   tt.fields.comps,
				authors: tt.fields.authors,
				tools:   tt.fields.tools,
				rels:    tt.fields.rels,
				logs:    tt.fields.logs,
			}
			if got := c.addSupplierName(tt.args.index); got != tt.want {
				t.Errorf("cdxDoc.addSupplierName() = %v, want %v", got, tt.want)
			}
		})
	}
}
