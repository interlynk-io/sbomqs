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
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/sbom/sbomfakes"
)

func sampleDocs() []sbom.Document {
	var fakeLicRestrictive = &sbomfakes.FakeLicense{}
	var fakeRestComp = &sbomfakes.FakeComponent{}
	var fakeDoc2 = &sbomfakes.FakeDocument{}
	fakeLicRestrictive.NameReturns("GPL-3.0")
	fakeRestComp.LicensesReturns([]sbom.License{fakeLicRestrictive})
	fakeDoc2.ComponentsReturns([]sbom.Component{fakeRestComp})

	var fakeLicNonRestrictive = &sbomfakes.FakeLicense{}
	var fakeComp = &sbomfakes.FakeComponent{}
	var fakeDoc = &sbomfakes.FakeDocument{}
	fakeLicNonRestrictive.NameReturns("MIT")
	fakeComp.LicensesReturns([]sbom.License{fakeLicNonRestrictive})
	fakeDoc.ComponentsReturns([]sbom.Component{fakeComp})

	var fakeComp3 = &sbomfakes.FakeComponent{}
	var fakeDoc3 = &sbomfakes.FakeDocument{}
	fakeComp3.LicensesReturns([]sbom.License{})
	fakeDoc3.ComponentsReturns([]sbom.Component{fakeComp3})

	return []sbom.Document{fakeDoc, fakeDoc2, fakeDoc3}
}

func Test_compWithRestrictedLicensesScore(t *testing.T) {
	testDocs := sampleDocs()

	type args struct {
		d sbom.Document
	}
	tests := []struct {
		name string
		args args
		want float64
	}{
		{"Doc has no restrictive licenses", args{d: testDocs[0]}, 10.0},
		{"Doc has restrictive licenses", args{d: testDocs[1]}, 0.0},
		{"Doc has no licenses", args{d: testDocs[2]}, 0.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compWithRestrictedLicensesScore(tt.args.d); got.score != tt.want {
				t.Errorf("compWithRestrictedLicensesScore() = %v, want %v", got.score, tt.want)
			}
		})
	}
}
