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

package compliance

import (
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"gotest.tools/assert"
)

func createSpdxDummyDocumentNtia() sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.CreationTimestamp = "2023-05-04T09:33:40Z"

	var creators []sbom.GetTool
	creator := sbom.Tool{
		Name: "syft",
	}
	creators = append(creators, creator)

	pack1 := sbom.NewComponent()
	pack1.Version = "v0.7.1"
	pack1.Name = "tool-golang"
	pack1.ID = "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1"

	pack2 := sbom.NewComponent()
	pack2.Version = "v1.0.1"
	pack2.Name = "spdx-gordf"
	pack2.ID = "github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"

	supplier := sbom.Supplier{
		Email: "hello@interlynk.io",
	}
	pack1.Supplier = supplier

	extRef := sbom.ExternalReference{
		RefType: "purl",
	}

	var primary sbom.PrimaryComponentInfo
	primary.ID = pack1.ID
	primary.Name = pack1.Name
	primary.Version = pack1.Version
	primary.Type = "application"
	primary.Present = true

	var rel sbom.Relationship

	rel.From = pack1.ID
	rel.To = pack2.ID
	rel.Type = "DEPENDS_ON"

	var relations []sbom.GetRelationship
	relations = append(relations, rel)

	var externalReferences []sbom.GetExternalReference
	externalReferences = append(externalReferences, extRef)
	pack1.ExternalRefs = externalReferences

	var packages []sbom.GetComponent
	packages = append(packages, pack1, pack2)

	doc := sbom.SpdxDoc{
		SpdxSpec:         s,
		Comps:            packages,
		SpdxTools:        creators,
		Relationships:    relations,
		PrimaryComponent: primary,
	}
	return doc
}

type desiredNtia struct {
	score  float64
	result string
	key    int
	id     string
}

func TestNtiaSpdxSbomPass(t *testing.T) {
	doc := createSpdxDummyDocumentNtia()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desiredNtia
	}{
		{
			name:   "AutomationSpec",
			actual: ntiaAutomationSpec(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "spdx, json",
				key:    SBOM_MACHINE_FORMAT,
				id:     "Automation Support",
			},
		},
		{
			name:   "SbomCreator",
			actual: ntiaSbomCreator(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "syft",
				key:    SBOM_CREATOR,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "SbomCreatedTimestamp",
			actual: ntiaSbomCreatedTimestamp(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "2023-05-04T09:33:40Z",
				key:    SBOM_TIMESTAMP,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "SbomDependency",
			actual: ntiaSBOMRelationships(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "primary component declares 1 direct dependencies",
				key:    SBOM_DEPENDENCY,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "ComponentCreator",
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "hello@interlynk.io",
				key:    COMP_CREATOR,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "tool-golang",
				key:    COMP_NAME,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "purl:(1/1)",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     common.UniqueElementID(doc.Components()[0]),
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

func createCdxDummyDocumentNtia() sbom.Document {
	cdxSpec := sbom.NewSpec()
	cdxSpec.Version = "1.4"
	cdxSpec.SpecType = "cyclonedx"
	cdxSpec.CreationTimestamp = "2023-05-04T09:33:40Z"
	cdxSpec.Format = "xml"

	var authors []sbom.GetAuthor
	author := sbom.Author{
		Email: "hello@interlynk.io",
	}
	authors = append(authors, author)

	comp1 := sbom.NewComponent()
	comp1.Version = "v0.7.1"
	comp1.Name = "tool-golang"
	comp1.ID = "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1"

	comp2 := sbom.NewComponent()
	comp2.Version = "v1.0.1"
	comp2.Name = "spdx-gordf"
	comp2.ID = "github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"

	supplier := sbom.Supplier{
		Email: "hello@interlynk.io",
	}
	comp1.Supplier = supplier

	npurl := purl.NewPURL("vivek")

	comp1.Purls = []purl.PURL{npurl}

	extRef := sbom.ExternalReference{
		RefType: "purl",
	}

	var externalReferences []sbom.GetExternalReference
	externalReferences = append(externalReferences, extRef)
	comp1.ExternalRefs = externalReferences

	var components []sbom.GetComponent
	components = append(components, comp1, comp2)

	var primary sbom.PrimaryComponentInfo
	primary.ID = comp1.ID
	primary.Name = comp1.Name
	primary.Version = comp1.Version
	primary.Type = "application"
	primary.Present = true

	var dep sbom.Relationship
	dep.From = comp1.ID
	dep.To = comp2.ID
	dep.Type = "DEPENDS_ON"

	var relationships []sbom.GetRelationship
	relationships = append(relationships, dep)

	doc := sbom.CdxDoc{
		CdxSpec:          cdxSpec,
		Comps:            components,
		CdxAuthors:       authors,
		Relationships:    relationships,
		PrimaryComponent: primary,
	}
	return doc
}

func TestNtiaCdxSbomPass(t *testing.T) {
	doc := createCdxDummyDocumentNtia()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desiredNtia
	}{
		{
			name:   "AutomationSpec",
			actual: ntiaAutomationSpec(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "cyclonedx, xml",
				key:    SBOM_MACHINE_FORMAT,
				id:     "Automation Support",
			},
		},
		{
			name:   "SbomCreator",
			actual: ntiaSbomCreator(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "hello@interlynk.io",
				key:    SBOM_CREATOR,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "SbomCreatedTimestamp",
			actual: ntiaSbomCreatedTimestamp(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "2023-05-04T09:33:40Z",
				key:    SBOM_TIMESTAMP,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "SbomDependency",
			actual: ntiaSBOMRelationships(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "primary component declares 1 direct dependencies",
				key:    SBOM_DEPENDENCY,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "ComponentCreator",
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "hello@interlynk.io",
				key:    COMP_CREATOR,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "tool-golang",
				key:    COMP_NAME,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "vivek",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     common.UniqueElementID(doc.Components()[0]),
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

func createSpdxDummyDocumentFailNtia() sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-4.0"
	s.SpecType = "swid"
	s.Format = "fjson"
	s.CreationTimestamp = "2023-05-04"

	var creators []sbom.GetTool
	creator := sbom.Tool{
		Name: "",
	}
	creators = append(creators, creator)

	pack := sbom.NewComponent()
	pack.Version = ""
	pack.Name = ""

	supplier := sbom.Supplier{
		Email: "",
	}
	pack.Supplier = supplier

	extRef := sbom.ExternalReference{
		RefType: "purl",
	}

	var externalReferences []sbom.GetExternalReference
	externalReferences = append(externalReferences, extRef)
	pack.ExternalRefs = externalReferences

	var packages []sbom.GetComponent
	packages = append(packages, pack)

	depend := sbom.Relationship{
		From: "",
		To:   "",
		Type: "",
	}

	var dependencies []sbom.GetRelationship
	dependencies = append(dependencies, depend)

	doc := sbom.SpdxDoc{
		SpdxSpec:      s,
		Comps:         packages,
		SpdxTools:     creators,
		Relationships: dependencies,
	}
	return doc
}

func TestNTIASbomFail(t *testing.T) {
	doc := createSpdxDummyDocumentFailNtia()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desiredNtia
	}{
		{
			name:   "AutomationSpec",
			actual: ntiaAutomationSpec(doc),
			expected: desiredNtia{
				score:  0.0,
				result: "swid, fjson",
				key:    SBOM_MACHINE_FORMAT,
				id:     "Automation Support",
			},
		},
		{
			name:   "SbomCreator",
			actual: ntiaSbomCreator(doc),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    SBOM_CREATOR,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "SbomCreatedTimestamp",
			actual: ntiaSbomCreatedTimestamp(doc),
			expected: desiredNtia{
				score:  0.0,
				result: "2023-05-04",
				key:    SBOM_TIMESTAMP,
				id:     "SBOM Data Fields",
			},
		},
		{
			name:   "ComponentCreator",
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_CREATOR,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},

		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_NAME,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_VERSION,
				id:     common.UniqueElementID(doc.Components()[0]),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     common.UniqueElementID(doc.Components()[0]),
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
