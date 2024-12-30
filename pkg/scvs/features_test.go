package scvs

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"gotest.tools/assert"
)

func cdxDocWithTool() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM creation is automated and reproducible",
	}
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tool.Version = "9.1.2"
	tools = append(tools, tool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc, &p
}

func cdxToolWithoutVersion() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM creation is automated and reproducible",
	}
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tools = append(tools, tool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc, &p
}

func cdxToolWithoutName() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM creation is automated and reproducible",
	}
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tools = append(tools, tool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc, &p
}

type desired struct {
	feature string
	l1score string
	l2score string
	l3score string
	desc    string
}

func TestSBOMAutomationCreation(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "cdxSBOMWithToolNameAndVersion",
			actual: scvsSBOMAutomationCreationCheck(cdxDocWithTool()),
			expected: desired{
				feature: "SBOM creation is automated and reproducible",
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "SBOM creation is automated",
			},
		},
		{
			name:   "cdxSBOMWithToolWithoutVersion",
			actual: scvsSBOMAutomationCreationCheck(cdxToolWithoutVersion()),
			expected: desired{
				feature: "SBOM creation is automated and reproducible",
				// l1score: 10.0,
				l2score: red + bold + "✗" + reset,
				l3score: red + bold + "✗" + reset,
				desc:    "SBOM creation is non-automated",
			},
		},
		{
			name:   "cdxSBOMWithToolWithoutName",
			actual: scvsSBOMAutomationCreationCheck(cdxToolWithoutName()),
			expected: desired{
				feature: "SBOM creation is automated and reproducible",
				l2score: red + bold + "✗" + reset,
				l3score: red + bold + "✗" + reset,
				desc:    "SBOM creation is non-automated",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l1score, test.actual.l1Score, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.l2score, test.actual.l2Score, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Maturity mismatch for %s", test.name)
	}
}

func spdxSbomWithGlobalUniqID() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Each SBOM has global unique ID",
	}
	namespace := "https://anchore.com/syft/file/sbomqs-linux-amd64-ef8c4621-f421-44cd-8267-749e6cf75626"

	spec := sbom.NewSpec()
	spec.UniqID = namespace

	doc := sbom.SpdxDoc{
		SpdxSpec: spec,
	}
	return doc, &p
}

func cdxSbomWithGlobalUniqID() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Each SBOM has global unique ID",
	}
	serialNumber := "urn:uuid:59449365-e065-4fbe-aec6-6b2f852e8147"
	spec := sbom.NewSpec()
	spec.UniqID = serialNumber

	doc := sbom.CdxDoc{
		CdxSpec: spec,
	}
	return doc, &p
}

func TestSBOMWithGlobalUniqIDs(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "spdxSBOMWithGlobalUniqID",
			actual: scvsSBOMUniqIDCheck(spdxSbomWithGlobalUniqID()),
			expected: desired{
				feature: "Each SBOM has global unique ID",
				l1score: green + bold + "✓" + reset,
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "SBOM have global uniq ID",
			},
		},
		{
			name:   "cdxSBOMWithGlobalUniqID",
			actual: scvsSBOMUniqIDCheck(cdxSbomWithGlobalUniqID()),
			expected: desired{
				feature: "Each SBOM has global unique ID",
				l1score: green + bold + "✓" + reset,
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "SBOM have global uniq ID",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l1score, test.actual.l1Score, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.l2score, test.actual.l2Score, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Maturity mismatch for %s", test.name)
	}
}

func sbomWithTimestamp() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM is timestamped",
	}

	s := sbom.NewSpec()
	s.CreationTimestamp = "2020-04-13T20:20:39+00:00"
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc, &p
}

func TestSBOMHasTimestamp(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "sbomWithTimestamp",
			actual: scvsSBOMTimestampCheck(sbomWithTimestamp()),
			expected: desired{
				feature: "SBOM is timestamped",
				l1score: green + bold + "✓" + reset,
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "SBOM is timestamped",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l1score, test.actual.l1Score, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.l2score, test.actual.l2Score, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Maturity mismatch for %s", test.name)
	}
}

// func sbomWithTimestamp() (d sbom.Document, c *scvsCheck) {
// 	p := scvsCheck{
// 		Key: "SBOM is timestamped",
// 	}

// 	s := sbom.NewSpec()
// 	s.CreationTimestamp = "2020-04-13T20:20:39+00:00"
// 	doc := sbom.CdxDoc{
// 		CdxSpec: s,
// 	}
// 	return doc, &p
// }

func docWithPrimaryComponent() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM contains metadata about the asset or software the SBOM describes",
	}

	primary := sbom.PrimaryComp{}
	primary.Present = true
	primary.ID = "git@github.com:interlynk/sbomqs.git"

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc, &p
}

func TestSBOMWithPrimaryComp(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "sbomWithPrimaryComp",
			actual: scvsSBOMPrimaryCompCheck(docWithPrimaryComponent()),
			expected: desired{
				feature: "SBOM contains metadata about the asset or software the SBOM describes",
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "SBOM have primary comp",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		// assert.Equal(t, test.expected.l1score, test.actual.l1Score, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.l2score, test.actual.l2Score, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Maturity mismatch for %s", test.name)
	}
}

func docWithIdentityCheck() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "SBOM contains metadata about the asset or software the SBOM describes",
	}

	primary := sbom.PrimaryComp{}
	primary.Present = true
	primary.ID = "git@github.com:interlynk/sbomqs.git"

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc, &p
}

type externalRef struct {
	refCategory string
	refType     string
	refLocator  string
}

func docWithCPE() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Component identifiers are derived from their native ecosystems (if applicable)",
	}

	urls := []cpe.CPE{}
	comps := []sbom.GetComponent{}
	comp := sbom.NewComponent()

	comp.Name = "glibc"
	comp.Spdxid = "SPDXRef-git-github.com-glibc-afb1ddc0824ce0052d72ac0d6917f144a1207424"

	ext := externalRef{
		// refCategory: "SECURITY",
		// refType:     "cpe23Type",
		refLocator: "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*",
	}

	prl := cpe.NewCPE(ext.refLocator)
	urls = append(urls, prl)
	comp.Cpes = urls

	comps = append(comps, comp)

	doc := sbom.SpdxDoc{
		Comps: comps,
	}
	return doc, &p
}

func docWithPurl() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Component point of origin is identified in a consistent, machine readable format (e.g. PURL)",
	}
	comps := []sbom.GetComponent{}

	comp := sbom.NewComponent()
	comp.Name = "acme"
	PackageURL := "pkg:npm/acme/component@1.0.0"

	prl := purl.NewPURL(PackageURL)
	comp.Purls = []purl.PURL{prl}
	comps = append(comps, comp)

	doc := sbom.CdxDoc{
		Comps: comps,
	}
	return doc, &p
}

func TestComponentWithID(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "sbomWithCPE",
			actual: scvsCompHasIdentityIDCheck(docWithCPE()),
			expected: desired{
				feature: "Component identifiers are derived from their native ecosystems (if applicable)",
				l1score: green + bold + "✓" + reset,
				l2score: green + bold + "✓" + reset,
				l3score: green + bold + "✓" + reset,
				desc:    "1/1 comp have Identity ID's",
			},
		},
		{
			name:   "sbomWithPurl",
			actual: scvsCompHasOriginIDCheck(docWithPurl()),
			expected: desired{
				feature: "Component point of origin is identified in a consistent, machine readable format (e.g. PURL)",
				l3score: green + bold + "✓" + reset,
				desc:    "1/1 comp have Origin ID's",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Maturity mismatch for %s", test.name)
	}
}

func compWithCopyright() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Components defined in SBOM have valid copyright statements",
	}
	comps := []sbom.GetComponent{}
	copyright := "2013-2023 The Cobra Authors"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comps = append(comps, comp)

	doc := sbom.CdxDoc{
		Comps: comps,
	}
	return doc, &p
}

func TestComponentWithCopyright(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "compWithCopyright",
			actual: scvsCompHasCopyright(compWithCopyright()),
			expected: desired{
				feature: "Components defined in SBOM have valid copyright statements",
				l3score: green + bold + "✓" + reset,
				desc:    "1/1 comp has Copyright",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Description mismatch for %s", test.name)

	}
}

func compWithHigherChecksum() (d sbom.Document, c *scvsCheck) {
	p := scvsCheck{
		Key: "Components defined in SBOM have one or more file hashes (SHA-256, SHA-512, etc)",
	}
	comps := []sbom.GetComponent{}
	chks := []sbom.GetChecksum{}

	ck := sbom.Checksum{}
	ck.Alg = "SHA256"
	ck.Content = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"

	chks = append(chks, ck)

	comp := sbom.Component{
		Checksums: chks,
	}
	comps = append(comps, comp)

	doc := sbom.SpdxDoc{
		Comps: comps,
	}
	return doc, &p
}

func TestComponentWithHash(t *testing.T) {
	testCases := []struct {
		name     string
		actual   scvsScore
		expected desired
	}{
		{
			name:   "compWithChecksum",
			actual: scvsCompHashCheck(compWithHigherChecksum()),
			expected: desired{
				feature: "Components defined in SBOM have one or more file hashes (SHA-256, SHA-512, etc)",
				l3score: green + bold + "✓" + reset,
				desc:    "1/1 comp has Checksum",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.feature, test.actual.feature, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.l3score, test.actual.l3Score, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.desc, test.actual.descr, "Description mismatch for %s", test.name)

	}
}
