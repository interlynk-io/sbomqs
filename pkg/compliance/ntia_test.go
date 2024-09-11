package compliance

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
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

	pack := sbom.NewComponent()
	pack.Version = "v0.7.1"
	pack.Name = "core-js"

	supplier := sbom.Supplier{
		Email: "hello@interlynk.io",
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

	depend := sbom.Relation{
		From: "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1",
		To:   "github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd",
	}
	var dependencies []sbom.GetRelation
	dependencies = append(dependencies, depend)

	doc := sbom.SpdxDoc{
		SpdxSpec:  s,
		Comps:     packages,
		SpdxTools: creators,
		Rels:      dependencies,
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
		actual   *record
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
			name:   "ComponentCreator",
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "hello@interlynk.io",
				key:    PACK_SUPPLIER,
				id:     doc.Components()[0].GetName(),
			},
		},

		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "core-js",
				key:    COMP_NAME,
				id:     doc.Components()[0].GetName(),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     doc.Components()[0].GetName(),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "purl:(1/1)",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     doc.Components()[0].GetName(),
			},
		},
		{
			name:   "ComponentDependencies",
			actual: ntiaComponentDependencies(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "gordf",
				key:    COMP_DEPTH,
				id:     doc.Components()[0].GetName(),
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.checkKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.id, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.checkValue, "Result mismatch for %s", test.name)
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

	comp := sbom.NewComponent()
	comp.Version = "v0.7.1"
	comp.Name = "core-js"

	supplier := sbom.Supplier{
		Email: "hello@interlynk.io",
	}
	comp.Supplier = supplier

	npurl := purl.NewPURL("vivek")

	comp.Purls = []purl.PURL{npurl}

	extRef := sbom.ExternalReference{
		RefType: "purl",
	}

	var externalReferences []sbom.GetExternalReference
	externalReferences = append(externalReferences, extRef)
	comp.ExternalRefs = externalReferences

	var components []sbom.GetComponent
	components = append(components, comp)

	doc := sbom.CdxDoc{
		CdxSpec:    cdxSpec,
		Comps:      components,
		CdxAuthors: authors,
	}
	return doc
}

func TestNtiaCdxSbomPass(t *testing.T) {
	doc := createCdxDummyDocumentNtia()
	testCases := []struct {
		name     string
		actual   *record
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
			name:   "ComponentCreator",
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "hello@interlynk.io",
				key:    COMP_CREATOR,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "core-js",
				key:    COMP_NAME,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "vivek",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     doc.Components()[0].GetID(),
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.checkKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.id, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.checkValue, "Result mismatch for %s", test.name)
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

	depend := sbom.Relation{
		From: "",
		To:   "",
	}
	var dependencies []sbom.GetRelation
	dependencies = append(dependencies, depend)

	doc := sbom.SpdxDoc{
		SpdxSpec:  s,
		Comps:     packages,
		SpdxTools: creators,
		Rels:      dependencies,
	}
	return doc
}

func TestNTIASbomFail(t *testing.T) {
	doc := createSpdxDummyDocumentFailNtia()
	testCases := []struct {
		name     string
		actual   *record
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
				id:     doc.Components()[0].GetID(),
			},
		},

		{
			name:   "ComponentName",
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_NAME,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			name:   "ComponentVersion",
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_VERSION,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			name:   "ComponentOtherUniqIDs",
			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  0.0,
				result: "",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     doc.Components()[0].GetID(),
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.checkKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.id, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.checkValue, "Result mismatch for %s", test.name)
	}
}
