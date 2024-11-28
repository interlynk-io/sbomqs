package compliance

import (
	"testing"

	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"gotest.tools/assert"
)

func spdxDocWithNoVulnerability() sbom.Document {
	doc := sbom.SpdxDoc{
		Vuln: nil,
	}
	return doc
}

func TestBSIV2SPDXSbomVulnerability(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX SBOM with no vulnerability",
			actual: bsiV2Vulnerabilities(spdxDocWithNoVulnerability()),
			expected: desired{
				score:  10.0,
				result: "no-vulnerability",
				key:    SBOM_VULNERABILITES,
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

func cdxDocWithZeroVulnerability() sbom.Document {
	doc := sbom.CdxDoc{
		Vuln: nil,
	}
	return doc
}

func cdxDocWithOneVulnerability() sbom.Document {
	vuln := sbom.Vulnerability{
		Id: "CVE-2018-7489",
	}

	doc := sbom.CdxDoc{
		Vuln: []sbom.GetVulnerabilities{vuln},
	}
	return doc
}

func cdxDocWithMultipleVulnerability() sbom.Document {
	vuln1 := sbom.Vulnerability{
		Id: "CVE-2018-7489",
	}
	vuln2 := sbom.Vulnerability{
		Id: "CVE-2021-44228",
	}

	doc := sbom.CdxDoc{
		Vuln: []sbom.GetVulnerabilities{vuln1, vuln2},
	}
	return doc
}

func TestBSIV2CDXSbomVulnerability(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with zero vulnerability",
			actual: bsiV2Vulnerabilities(cdxDocWithZeroVulnerability()),
			expected: desired{
				score:  10.0,
				result: "no-vulnerability",
				key:    SBOM_VULNERABILITES,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with One vulnerability",
			actual: bsiV2Vulnerabilities(cdxDocWithOneVulnerability()),
			expected: desired{
				score:  0.0,
				result: "CVE-2018-7489",
				key:    SBOM_VULNERABILITES,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with Multiple vulnerability",
			actual: bsiV2Vulnerabilities(cdxDocWithMultipleVulnerability()),
			expected: desired{
				score:  0.0,
				result: "CVE-2018-7489, CVE-2021-44228",
				key:    SBOM_VULNERABILITES,
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
