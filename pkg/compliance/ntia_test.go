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
		Email: "vivekkumarsahu650@gmail.com",
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
		From: "SPDXRef-Package-go-module-github.com-abc",
		To:   "SPDXRef-Package-go-module-github.com-xyz",
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
		actual   *record
		expected desiredNtia
	}{
		{
			actual: ntiaAutomationSpec(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "spdx",
				key:    SBOM_SPEC,
				id:     "SBOM format",
			},
		},
		{
			actual: ntiaSbomCreator(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "syft",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			actual: ntiaSbomCreatedTimestamp(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "2023-05-04T09:33:40Z",
				key:    SBOM_TIMESTAMP,
				id:     "doc",
			},
		},
		{
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "vivekkumarsahu650@gmail.com",
				key:    PACK_SUPPLIER,
				id:     doc.Components()[0].GetID(),
			},
		},

		{
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "core-js",
				key:    COMP_NAME,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			actual: ntiaComponentOtherUniqIds(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "purl:(1/1)",
				key:    PACK_EXT_REF,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			actual: ntiaComponentDependencies(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "SPDXRef-Package-go-module-github.com-abc, SPDXRef-Package-go-module-github.com-xyz",
				key:    COMP_DEPTH,
				id:     doc.Components()[0].GetID(),
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.score)
		assert.Equal(t, test.expected.key, test.actual.check_key)
		assert.Equal(t, test.expected.id, test.actual.id)
		assert.Equal(t, test.expected.result, test.actual.check_value)
	}
}

func createCdxDummyDocumentNtia() sbom.Document {
	cdxSpec := sbom.NewSpec()
	cdxSpec.Version = "1.4"
	cdxSpec.SpecType = "cyclonedx"
	cdxSpec.CreationTimestamp = "2023-05-04T09:33:40Z"

	var authors []sbom.GetAuthor
	author := sbom.Author{
		Email: "vivekkumarsahu650@gmail.com",
	}
	authors = append(authors, author)

	comp := sbom.NewComponent()
	comp.Version = "v0.7.1"
	comp.Name = "core-js"

	supplier := sbom.Supplier{
		Email: "vivekkumarsahu650@gmail.com",
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
		actual   *record
		expected desiredNtia
	}{
		{
			actual: ntiaAutomationSpec(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "cyclonedx",
				key:    SBOM_SPEC,
				id:     "SBOM format",
			},
		},
		{
			actual: ntiaSbomCreator(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "vivekkumarsahu650@gmail.com",
				key:    SBOM_CREATOR,
				id:     "doc",
			},
		},
		{
			actual: ntiaSbomCreatedTimestamp(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "2023-05-04T09:33:40Z",
				key:    SBOM_TIMESTAMP,
				id:     "doc",
			},
		},
		{
			actual: ntiaComponentCreator(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "vivekkumarsahu650@gmail.com",
				key:    COMP_CREATOR,
				id:     doc.Components()[0].GetID(),
			},
		},

		{
			actual: ntiaComponentName(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "core-js",
				key:    COMP_NAME,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			actual: ntiaComponentVersion(doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "v0.7.1",
				key:    COMP_VERSION,
				id:     doc.Components()[0].GetID(),
			},
		},
		{
			actual: ntiaComponentOtherUniqIds(doc, doc.Components()[0]),
			expected: desiredNtia{
				score:  10.0,
				result: "vivek",
				key:    COMP_OTHER_UNIQ_IDS,
				id:     doc.Components()[0].GetID(),
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.score)
		assert.Equal(t, test.expected.key, test.actual.check_key)
		assert.Equal(t, test.expected.id, test.actual.id)
		assert.Equal(t, test.expected.result, test.actual.check_value)
	}
}

// func createFailureDummyDocumentNtia() sbom.Document {
// 	s := sbom.NewSpec()
// 	s.Version = ""
// 	s.Format = "xml"
// 	s.SpecType = "cyclonedx"
// 	s.Name = ""
// 	s.Namespace = ""
// 	s.Organization = ""
// 	s.CreationTimestamp = "wrong-time-format"
// 	s.Spdxid = ""
// 	s.Comment = ""
// 	lics := licenses.CreateCustomLicense("", "")
// 	s.Licenses = append(s.Licenses, lics)

// 	var tools []sbom.GetTool
// 	tool := sbom.Tool{
// 		Name: "",
// 	}
// 	tools = append(tools, tool)

// 	pack := sbom.NewComponent()
// 	pack.Version = ""
// 	pack.Name = ""
// 	pack.Spdxid = ""
// 	pack.CopyRight = "NOASSERTION"
// 	pack.FileAnalyzed = false
// 	pack.Id = ""
// 	pack.PackageLicenseConcluded = "NONE"
// 	pack.PackageLicenseDeclared = "NOASSERTION"
// 	pack.DownloadLocation = ""

// 	supplier := sbom.Supplier{
// 		Email: "",
// 	}
// 	pack.Supplier = supplier

// 	checksum := sbom.Checksum{
// 		Alg:     "SHA-1",
// 		Content: "443238d9cf19f77ccc8cdda3ba5421ea9ea2bc78",
// 	}

// 	var checksums []sbom.GetChecksum
// 	checksums = append(checksums, checksum)
// 	pack.Checksums = checksums

// 	extRef := sbom.ExternalReference{
// 		RefType: "cpe23Type",
// 	}
// 	var externalReferences []sbom.GetExternalReference
// 	externalReferences = append(externalReferences, extRef)
// 	pack.ExternalRefs = externalReferences

// 	var packages []sbom.GetComponent
// 	packages = append(packages, pack)

// 	doc := sbom.SpdxDoc{
// 		SpdxSpec:  s,
// 		Comps:     packages,
// 		SpdxTools: tools,
// 	}
// 	return doc
// }

// func TestOctSbomFail(t *testing.T) {
// 	doc := createFailureDummyDocument()
// 	testCases := []struct {
// 		actual   *record
// 		expected desired
// 	}{
// 		{
// 			actual: octSpec(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "cyclonedx",
// 				key:    SBOM_SPEC,
// 				id:     "SBOM Format",
// 			},
// 		},
// 		{
// 			actual: octSbomName(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_NAME,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octSbomNamespace(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_NAMESPACE,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octSbomOrganization(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_ORG,
// 				id:     "SBOM Build Information",
// 			},
// 		},
// 		{
// 			actual: octSbomComment(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_COMMENT,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octSbomTool(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_TOOL,
// 				id:     "SBOM Build Information",
// 			},
// 		},
// 		{
// 			actual: octSbomLicense(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_LICENSE,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octSpecVersion(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_SPEC_VERSION,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octCreatedTimestamp(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "wrong-time-format",
// 				key:    SBOM_TIMESTAMP,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octSpecSpdxID(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_SPDXID,
// 				id:     "SPDX Elements",
// 			},
// 		},
// 		{
// 			actual: octMachineFormat(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "cyclonedx, xml",
// 				key:    SBOM_MACHINE_FORMAT,
// 				id:     "Machine Readable Data Format",
// 			},
// 		},
// 		{
// 			actual: octHumanFormat(doc),
// 			expected: desired{
// 				score:  0.0,
// 				result: "xml",
// 				key:    SBOM_HUMAN_FORMAT,
// 				id:     "Human Readable Data Format",
// 			},
// 		},
// 		{
// 			actual: octPackageName(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_NAME,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageVersion(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_VERSION,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageSpdxID(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_SPDXID,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageSupplier(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_SUPPLIER,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageHash(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_HASH,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageExternalRefs(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "cpe23Type",
// 				key:    PACK_EXT_REF,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageCopyright(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "NOASSERTION",
// 				key:    PACK_COPYRIGHT,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageFileAnalyzed(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "no",
// 				key:    PACK_FILE_ANALYZED,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageConLicense(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "NONE",
// 				key:    PACK_LICENSE_CON,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageDecLicense(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "NOASSERTION",
// 				key:    PACK_LICENSE_DEC,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 		{
// 			actual: octPackageDownloadUrl(doc.Components()[0]),
// 			expected: desired{
// 				score:  0.0,
// 				result: "",
// 				key:    PACK_DOWNLOAD_URL,
// 				id:     doc.Components()[0].GetID(),
// 			},
// 		},
// 	}

// 	for _, test := range testCases {
// 		assert.Equal(t, test.expected.score, test.actual.score)
// 		assert.Equal(t, test.expected.key, test.actual.check_key)
// 		assert.Equal(t, test.expected.id, test.actual.id)
// 		assert.Equal(t, test.expected.result, test.actual.check_value)
// 	}
// }
