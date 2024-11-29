// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"strings"
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"gotest.tools/assert"
)

func cdxDocWithSpec() sbom.Document {
	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec: spec,
	}
	return doc
}

func spdxDocWithSpec() sbom.Document {
	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	doc := sbom.SpdxDoc{
		SpdxSpec: spec,
	}
	return doc
}

func TestBSIWithSbomSpecFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "sbomWithCdxSpec",
			actual: bsiSpec(cdxDocWithSpec()),
			expected: desired{
				score:  10.0,
				result: "cyclonedx",
				key:    SBOM_SPEC,
				id:     "doc",
			},
		},
		{
			name:   "sbomWithSpdxSpec",
			actual: bsiSpec(spdxDocWithSpec()),
			expected: desired{
				score:  10.0,
				result: "spdx",
				key:    SBOM_SPEC,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

func cdxDocWithSpecVersion() sbom.Document {
	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	spec.Version = "1.4"
	doc := sbom.CdxDoc{
		CdxSpec: spec,
	}
	return doc
}

func cdxDocWithHigherSpecVersion() sbom.Document {
	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	spec.Version = "1.5"
	doc := sbom.CdxDoc{
		CdxSpec: spec,
	}
	return doc
}

func spdxDocWithSpecVersion() sbom.Document {
	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	spec.Version = "SPDX-2.2"
	doc := sbom.SpdxDoc{
		SpdxSpec: spec,
	}
	return doc
}

func TestBSIWithSbomSpecVersionFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "cdxSbomWithSpecVersion1.4",
			actual: bsiV2SpecVersion(cdxDocWithSpecVersion()),
			expected: desired{
				score:  0.0,
				result: "1.4",
				key:    SBOM_SPEC_VERSION,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithSpecVersion1.5",
			actual: bsiV2SpecVersion(cdxDocWithHigherSpecVersion()),
			expected: desired{
				score:  10.0,
				result: "1.5",
				key:    SBOM_SPEC_VERSION,
				id:     "doc",
			},
		},
		{
			name:   "apdxSbomWithSpecVersion2.2",
			actual: bsiV2SpecVersion(spdxDocWithSpecVersion()),
			expected: desired{
				score:  10.0,
				result: "SPDX-2.2",
				key:    SBOM_SPEC_VERSION,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

// no such lifecycle field in spdx
func spdxDocWithLifecycles() sbom.Document {
	creatorComment := "hellow, this is sbom build phase"

	doc := sbom.SpdxDoc{
		Lifecycle: creatorComment,
	}
	return doc
}

func cdxDocWithLifecycles() sbom.Document {
	doc := sbom.CdxDoc{
		Lifecycle: []string{"build"},
	}
	return doc
}

func TestBSIWithBuildPhaseField(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxSbomWithCustomLifecycle",
			actual: bsiBuildPhase(spdxDocWithLifecycles()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_BUILD,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithBuildLifecycle",
			actual: bsiBuildPhase(cdxDocWithLifecycles()),
			expected: desired{
				score:  10.0,
				result: "build",
				key:    SBOM_BUILD,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

func spdxDocWithSbomAuthorAsPerson() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Jane Doe"

	author.AuthorType = "person"
	author.Email = "janedoe@gmail.com"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func spdxDocWithSbomAuthorAsOrganization() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Interlynk"

	author.AuthorType = "organization"
	author.Email = "support@interlynk.io"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func spdxDocWithSbomAuthorAsPersonWithMissingEmail() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Jane Doe"

	author.AuthorType = "person"
	// author.Email = "janedoe@gmail.com"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func spdxDocWithSbomAuthorAsOrganizationWithMissingEmail() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Interlynk"

	author.AuthorType = "organization"
	// author.Email = "support@interlynk.io"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorAsPerson() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomWithManufacturer() sbom.Document {
	manufacture := sbom.Manufacturer{
		Name:  "interlynk",
		Email: "support@interlynk.io",
	}

	doc := sbom.CdxDoc{
		CdxManufacturer: manufacture,
	}
	return doc
}

func cdxDocWithSbomWithMissingManufacturerEmail() sbom.Document {
	manufacture := sbom.Manufacturer{
		Name: "interlynk",
	}

	doc := sbom.CdxDoc{
		CdxManufacturer: manufacture,
	}
	return doc
}

func cdxDocWithSbomWithSupplier() sbom.Document {
	supplier := sbom.Supplier{
		Name:  "interlynk",
		Email: "help@interlynk.io",
	}

	doc := sbom.CdxDoc{
		CdxSupplier: supplier,
	}
	return doc
}

func cdxDocWithSbomWithMissingSupplierEmail() sbom.Document {
	supplier := sbom.Supplier{
		Name: "interlynk",
	}

	doc := sbom.CdxDoc{
		CdxSupplier: supplier,
	}
	return doc
}

func TestBsiWithCreatorField(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxSbomWithAuthorAsPerson",
			actual: bsiCreator(spdxDocWithSbomAuthorAsPerson()),
			expected: desired{
				score:  10.0,
				result: "janedoe@gmail.com",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "spdxSbomWithAuthorAsOrganization",
			actual: bsiCreator(spdxDocWithSbomAuthorAsOrganization()),
			expected: desired{
				score:  10.0,
				result: "support@interlynk.io",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "spdxSbomWithAuthorAsPersonMissingEmail",
			actual: bsiCreator(spdxDocWithSbomAuthorAsPersonWithMissingEmail()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "spdxSbomWithAuthorAsOrganizationMissingEmail",
			actual: bsiCreator(spdxDocWithSbomAuthorAsOrganizationWithMissingEmail()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithManufacturer",
			actual: bsiCreator(cdxDocWithSbomWithManufacturer()),
			expected: desired{
				score:  10.0,
				result: "support@interlynk.io",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithSupplier",
			actual: bsiCreator(cdxDocWithSbomWithSupplier()),
			expected: desired{
				score:  10.0,
				result: "help@interlynk.io",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithManufacturerMissingEmail",
			actual: bsiCreator(cdxDocWithSbomWithMissingManufacturerEmail()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithSupplierMissingEmail",
			actual: bsiCreator(cdxDocWithSbomWithMissingSupplierEmail()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

func sbomDocWithTimestamp() sbom.Document {
	s := sbom.NewSpec()
	s.CreationTimestamp = "2020-04-13T20:20:39+00:00"
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc
}

func TestBSIWithTimestampField(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxSbomWithTimestamp",
			actual: bsiTimestamp(sbomDocWithTimestamp()),
			expected: desired{
				score:  10.0,
				result: "2020-04-13T20:20:39+00:00",
				key:    SBOM_TIMESTAMP,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

func spdxDocWithURI() sbom.Document {
	s := sbom.NewSpec()
	documentNamespace := "https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg"
	s.Uri = documentNamespace
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func cdxDocWithURI() sbom.Document {
	s := sbom.NewSpec()
	serialNumber := "urn:uuid:3337e3a3-62e6-4cbb-abf5-51284a43f9f2/1"
	s.Uri = serialNumber
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc
}

func TestBSIWithURIField(t *testing.T) {
	uri := "https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg"
	brokenResult := breakLongString(uri, 50)
	finalResult := strings.Join(brokenResult, "\n")

	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxSbomWithSbomURI",
			actual: bsiSbomURI(spdxDocWithURI()),
			expected: desired{
				score:  10.0,
				result: finalResult,
				key:    SBOM_URI,
				id:     "doc",
			},
		},
		{
			name:   "cdxSbomWithSbomURI",
			actual: bsiSbomURI(cdxDocWithURI()),
			expected: desired{
				score:  10.0,
				result: "urn:uuid:3337e3a3-62e6-4cbb-abf5-51284a43f9f2/1",
				key:    SBOM_URI,
				id:     "doc",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}

func compWithName() sbom.GetComponent {
	name := "cyclonedx-go"
	comp := sbom.Component{
		Name: name,
	}
	return comp
}

func compWithVersion() sbom.GetComponent {
	name := "cyclonedx-go"
	version := "v1.6.0"

	comp := sbom.Component{
		Name:    name,
		Version: version,
	}
	return comp
}

func TestFsctComponentLevelOnSpdxAndCdx(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "compWithName",
			actual: bsiComponentName(compWithName()),
			expected: desired{
				score:  10.0,
				result: "cyclonedx-go",
				key:    COMP_NAME,
				id:     common.UniqueElementID(compWithName()),
			},
		},
		{
			name:   "compWithVersion",
			actual: bsiComponentVersion(compWithVersion()),
			expected: desired{
				score:  10.0,
				result: "v1.6.0",
				key:    COMP_VERSION,
				id:     common.UniqueElementID(compWithVersion()),
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}
