package compliance

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
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
				key:    SBOM_VULNERABILITIES,
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
		ID: "CVE-2018-7489",
	}

	doc := sbom.CdxDoc{
		Vuln: []sbom.GetVulnerabilities{vuln},
	}
	return doc
}

func cdxDocWithMultipleVulnerability() sbom.Document {
	vuln1 := sbom.Vulnerability{
		ID: "CVE-2018-7489",
	}
	vuln2 := sbom.Vulnerability{
		ID: "CVE-2021-44228",
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
				key:    SBOM_VULNERABILITIES,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with One vulnerability",
			actual: bsiV2Vulnerabilities(cdxDocWithOneVulnerability()),
			expected: desired{
				score:  0.0,
				result: "CVE-2018-7489",
				key:    SBOM_VULNERABILITIES,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with Multiple vulnerability",
			actual: bsiV2Vulnerabilities(cdxDocWithMultipleVulnerability()),
			expected: desired{
				score:  0.0,
				result: "CVE-2018-7489, CVE-2021-44228",
				key:    SBOM_VULNERABILITIES,
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

func spdxDocWithNoExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()

	s.ExternalDocReference = nil
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func spdxDocWithOneExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()
	spdxDocument := []string{"https://example.com/spdx/docs/toolsetX-v1.2"}
	s.ExternalDocReference = spdxDocument
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func spdxDocWithMultipleExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()
	spdxDocument := []string{"https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg", "https://example.com/spdx/docs/toolsetX-v1.2"}
	s.ExternalDocReference = spdxDocument
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func TestBSIV2SPDXSbomBomLinks(t *testing.T) {
	value := "https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg, https://example.com/spdx/docs/toolsetX-v1.2"
	wrappedURL := common.WrapText(value, 80)

	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX SBOM with no bom links",
			actual: bsiV2SbomLinks(spdxDocWithNoExtDocumentRefs()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_BOM_LINKS,
				id:     "doc",
			},
		},
		{
			name:   "SPDX SBOM with one bom links",
			actual: bsiV2SbomLinks(spdxDocWithOneExtDocumentRefs()),
			expected: desired{
				score:  10.0,
				result: "https://example.com/spdx/docs/toolsetX-v1.2",
				key:    SBOM_BOM_LINKS,
				id:     "doc",
			},
		},
		{
			name:   "SPDX SBOM with two bom links vulnerability",
			actual: bsiV2SbomLinks(spdxDocWithMultipleExtDocumentRefs()),
			expected: desired{
				score:  10.0,
				result: wrappedURL,
				key:    SBOM_BOM_LINKS,
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

func cdxDocWithNoExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()

	s.ExternalDocReference = nil
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc
}

func cxDocWithOneExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()
	extRefs := []string{"https://raw.githubusercontent.com/bomctl/bomctl-playground/main/examples/bomctl-container-image/app/bomctl_0.3.0_linux_amd64.tar.gz.spdx.json"}
	s.ExternalDocReference = extRefs
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func cxDocWithMultipleExtDocumentRefs() sbom.Document {
	s := sbom.NewSpec()
	extRefs := []string{"https://raw.githubusercontent.com/bomctl/bomctl-playground/main/examples/bomctl-container-image/app/bomctl_0.3.0_linux_amd64.tar.gz.spdx.json", "https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg"}
	s.ExternalDocReference = extRefs
	doc := sbom.SpdxDoc{
		SpdxSpec: s,
	}
	return doc
}

func TestBSIV2CDXSbomBomLinks(t *testing.T) {
	value := "https://raw.githubusercontent.com/bomctl/bomctl-playground/main/examples/bomctl-container-image/app/bomctl_0.3.0_linux_amd64.tar.gz.spdx.json"
	wrappedURL := common.WrapText(value, 80)

	value2 := "https://raw.githubusercontent.com/bomctl/bomctl-playground/main/examples/bomctl-container-image/app/bomctl_0.3.0_linux_amd64.tar.gz.spdx.json, https://interlynk.io/github.com%2Finterlynk-io%2Fsbomqs/0.0.15/qIP32aoJi0u5M_EjHeJHAg"
	wrappedURL2 := common.WrapText(value2, 80)

	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with no bom links",
			actual: bsiV2SbomLinks(cdxDocWithNoExtDocumentRefs()),
			expected: desired{
				score:  0.0,
				result: "",
				key:    SBOM_BOM_LINKS,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with one bom links",
			actual: bsiV2SbomLinks(cxDocWithOneExtDocumentRefs()),
			expected: desired{
				score:  10.0,
				result: wrappedURL,
				key:    SBOM_BOM_LINKS,
				id:     "doc",
			},
		},
		{
			name:   "CDX SBOM with one bom links",
			actual: bsiV2SbomLinks(cxDocWithMultipleExtDocumentRefs()),
			expected: desired{
				score:  10.0,
				result: wrappedURL2,
				key:    SBOM_BOM_LINKS,
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

func spdxDocWithExternalSignatureVerificationSuccessfully() sbom.Document {
	signature := "../../samples/signature-test-data/sbom.sig"
	publicKey := "../../samples/signature-test-data/public_key.pem"
	blob := "../../samples/signature-test-data/SPDXJSONExample-v2.3.spdx.json"
	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      blob,
	}
	doc := sbom.SpdxDoc{
		SignatureDetail: &sig,
	}
	return doc
}

// nolint:unused
func spdxDocWithExternalSignatureVerificationFailed() sbom.Document {
	signature := "../../samples/signature-test-data/sbom.sig"
	publicKey := "../../samples/signature-test-data/public_key.pem"
	blob := "../../samples/signature-test-data/SPDXJSONExample-v2.3.spdx.json"
	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      blob,
	}
	doc := sbom.SpdxDoc{
		SignatureDetail: &sig,
	}
	return doc
}

func TestSpdxSBOMWithSignature(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX SBOM with attested signatures",
			actual: bsiV2SbomSignature(spdxDocWithExternalSignatureVerificationSuccessfully()),
			expected: desired{
				score:  10.0,
				result: "Signature verification succeeded!",
				key:    SBOM_SIGNATURE,
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

func cdxDocWithEmbeddedSignature() sbom.Document {
	sbomFile := "../../samples/signature-test-data/stree-cdxgen-signed-sbom.cdx.json"
	standaloneSBOMFile, signatureRetrieved, publicKeyRetrieved, _ := common.RetrieveSignatureFromSBOM(nil, sbomFile)

	sig := sbom.Signature{
		SigValue:  signatureRetrieved,
		PublicKey: publicKeyRetrieved,
		Blob:      standaloneSBOMFile,
	}
	doc := sbom.SpdxDoc{
		SignatureDetail: &sig,
	}
	return doc
}

func TestCdxSBOMWithSignature(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with attested signatures",
			actual: bsiV2SbomSignature(cdxDocWithEmbeddedSignature()),
			expected: desired{
				score:  10.0,
				result: "Signature verification succeeded!",
				key:    SBOM_SIGNATURE,
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
