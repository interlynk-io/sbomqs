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

package sbom

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/mail"
	"strings"

	cydx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/swhid"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
	"github.com/interlynk-io/sbomqs/v2/pkg/validation"
	"github.com/samber/lo"
	"go.uber.org/zap"
)

var (
	cdxSpecVersions       = []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}
	cdxFileFormats        = []string{"json", "xml"}
	cdxPrimaryPurpose     = []string{"application", "framework", "library", "container", "operating-system", "device", "firmware", "file"}
	CdxSupportedLifecycle = []string{"design", "pre-build", "build", "post-build", "operations", "discovery", "decommission"}
)

type CdxDoc struct {
	doc              *cydx.BOM
	format           FileFormat
	ctx              context.Context
	CdxSpec          *Specs
	cdxValidSchema   bool
	Comps            []GetComponent
	CdxAuthors       []GetAuthor
	CdxTools         []GetTool
	Relationships    []GetRelationship
	logs             []string
	Lifecycle        []string
	CdxSupplier      GetSupplier
	CdxManufacturer  GetManufacturer
	Compositions     []GetComposition
	PrimaryComponent PrimaryComponentInfo
	Vuln             []GetVulnerabilities
	SignatureDetail  GetSignature
	rawContent       []byte // Store raw content for manual parsing
}

func newCDXDoc(ctx context.Context, f io.ReadSeeker, format FileFormat, _ Signature) (Document, error) {
	var err error
	log := logger.FromContext(ctx)
	log.Debug("Constructing new instance of cdx")
	// Read the content for manual parsing if needed
	rawContent, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	// Reset the reader for the decoder
	reader := bytes.NewReader(rawContent)

	var bom *cydx.BOM

	switch format {
	case FileFormatJSON:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(reader, cydx.BOMFileFormatJSON)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	case FileFormatXML:
		bom = new(cydx.BOM)
		decoder := cydx.NewBOMDecoder(reader, cydx.BOMFileFormatXML)
		if err = decoder.Decode(bom); err != nil {
			return nil, err
		}
	default:
		err = fmt.Errorf("unsupported cdx file format: %s", string(format))
	}

	doc := &CdxDoc{
		doc:        bom,
		format:     format,
		ctx:        ctx,
		rawContent: rawContent,
	}
	doc.parse()
	for _, l := range doc.Logs() {
		log.Debug(l)
	}
	return doc, err
}

func (c CdxDoc) PrimaryComp() GetPrimaryComponentInfo {
	return &c.PrimaryComponent
}

func (c CdxDoc) Spec() Spec {
	return *c.CdxSpec
}

func (c CdxDoc) Components() []GetComponent {
	return c.Comps
}

func (c CdxDoc) Authors() []GetAuthor {
	return c.CdxAuthors
}

func (c CdxDoc) Tools() []GetTool {
	return c.CdxTools
}

func (c CdxDoc) GetRelationships() []GetRelationship {
	return c.Relationships
}

func (c CdxDoc) GetOutgoingRelations(compID string) []GetRelationship {
	out := make([]GetRelationship, 0)

	for _, r := range c.Relationships {
		if r.GetFrom() == compID {
			out = append(out, r)
		}
	}
	return out
}

func (c CdxDoc) GetDirectDependencies(compID string, relTypes ...string) []GetComponent {
	deps := make([]GetComponent, 0)

	allKindOfRelationships := c.GetOutgoingRelations(compID)
	if len(allKindOfRelationships) == 0 {
		return deps
	}

	mapCompWithID := make(map[string]GetComponent)
	for _, comp := range c.Components() {
		mapCompWithID[comp.GetID()] = comp
	}

	for _, r := range allKindOfRelationships {
		if !relTypeAllowed(r.GetType(), relTypes) {
			continue
		}

		if dep, ok := mapCompWithID[r.GetTo()]; ok {
			deps = append(deps, dep)
		}
	}

	return deps
}

func (c CdxDoc) Logs() []string {
	return c.logs
}

func (c CdxDoc) Lifecycles() []string {
	return c.Lifecycle
}

func (c CdxDoc) Supplier() GetSupplier {
	return c.CdxSupplier
}

func (c CdxDoc) Manufacturer() GetManufacturer {
	return c.CdxManufacturer
}

func (c CdxDoc) Composition() []GetComposition {
	return c.Compositions
}

func (c CdxDoc) Vulnerabilities() []GetVulnerabilities {
	return c.Vuln
}

func (c CdxDoc) Signature() GetSignature {
	return c.SignatureDetail
}

func (c CdxDoc) SchemaValidation() bool {
	return c.cdxValidSchema
}

func (c *CdxDoc) parse() {
	c.parseDoc()
	c.parseSpec()
	c.parseSchemaValidation()
	c.parseAuthors()
	c.parseSupplier()
	c.parseManufacturer()
	c.parseTool()
	c.parseCompositions()
	c.parsePrimaryComponent()
	c.parseDependencies()
	c.parseVulnerabilities()
	// Parse signature if not already present
	if c.SignatureDetail == nil {
		c.parseSignature()
	}
	c.parseComps()
}

func (c *CdxDoc) addToLogs(log string) {
	c.logs = append(c.logs, log)
}

func (c *CdxDoc) parseDoc() {
	if c.doc == nil {
		c.addToLogs("cdx doc is not parsable")
		return
	}

	if c.doc.Metadata == nil {
		c.addToLogs("cdx doc is missing metadata")
		return
	}

	if c.doc.Metadata.Lifecycles == nil {
		c.addToLogs("cdx doc is missing lifecycles")
		return
	}

	c.Lifecycle = lo.Map(lo.FromPtr(c.doc.Metadata.Lifecycles), func(l cydx.Lifecycle, _ int) string {
		if l.Phase != "" {
			return string(l.Phase)
		}

		if l.Name != "" {
			return l.Name
		}

		return ""
	})
}

func (c *CdxDoc) parseSchemaValidation() {
	c.cdxValidSchema = false

	if c.format != FileFormatJSON {
		c.addToLogs("schema validation skipped: non-JSON SBOM")
		return
	}

	c.addToLogs(fmt.Sprintf("spec: %s, version: %s", c.Spec().GetSpecType(), c.Spec().GetVersion()))
	result := validation.Validate("cyclonedx", c.Spec().GetVersion(), c.rawContent)

	c.addToLogs(fmt.Sprintf("schema valid: %v", result.Valid))
	c.cdxValidSchema = result.Valid

	for _, l := range result.Logs {
		c.addToLogs(l)
	}
}

func (c *CdxDoc) parseSpec() {
	sp := NewSpec()
	sp.Format = string(c.format)
	sp.Version = c.doc.SpecVersion.String()
	sp.Name = string(SBOMSpecCDX)
	sp.isReqFieldsPresent = c.requiredFields()

	if c.doc.Metadata != nil {
		sp.CreationTimestamp = c.doc.Metadata.Timestamp
		if c.doc.Metadata.Licenses != nil {
			sp.Licenses = aggregateLicenses(*c.doc.Metadata.Licenses, "")
		}
	}
	sp.Namespace = c.doc.SerialNumber
	sp.SpecType = string(SBOMSpecCDX)

	if c.doc.SerialNumber != "" && strings.HasPrefix(sp.Namespace, "urn:uuid:") {
		sp.URI = fmt.Sprintf("%s/%d", c.doc.SerialNumber, c.doc.Version)
	}

	if c.doc.ExternalReferences != nil {
		for _, extRefs := range *c.doc.ExternalReferences {
			if extRefs.Type == "bom" {
				sp.ExternalDocReference = append(sp.ExternalDocReference, extRefs.URL)
			}
		}
	}

	c.CdxSpec = sp
}

func (c *CdxDoc) parseVulnerabilities() {
	if c.doc.Vulnerabilities != nil {
		for _, v := range *c.doc.Vulnerabilities {
			if v.ID != "" {
				vuln := Vulnerability{}
				vuln.ID = v.ID
				c.Vuln = append(c.Vuln, vuln)
			}
		}
	}
}

// parseSignature extracts signature information from CyclonDX BOM
func (c *CdxDoc) parseSignature() {
	log := logger.FromContext(c.ctx)
	log.Debug("Parsing signature from raw SBOM")

	// Since cyclonedx-go doesn't properly unmarshal signatures yet,
	// we need to parse it manually from the raw JSON
	if c.format != FileFormatJSON {
		return // Only JSON format is supported for now
	}

	var rawBOM map[string]interface{}
	if err := json.Unmarshal(c.rawContent, &rawBOM); err != nil {
		log.Error("Error unmarshalling raw JSON", zap.Error(err))
		return
	}

	sigData, ok := rawBOM["signature"]
	if !ok || sigData == nil {
		return // No signature present
	}

	sigMap, ok := sigData.(map[string]interface{})
	if !ok {
		return
	}

	// Parse the signature based on its structure
	var sig *Signature

	// Check for single signer format (direct algorithm/value)
	if algorithm, ok := sigMap["algorithm"].(string); ok {
		// Single signer format
		sig = &Signature{
			Algorithm: algorithm,
		}

		if keyID, ok := sigMap["keyId"].(string); ok {
			sig.KeyID = keyID
		}

		if value, ok := sigMap["value"].(string); ok {
			sig.SigValue = value
		}

		// Parse public key
		if pubKeyData, ok := sigMap["publicKey"].(map[string]interface{}); ok {
			sig.PublicKey = c.parsePublicKey(pubKeyData)
		}

		// Parse certificate path
		if certPath, ok := sigMap["certificatePath"].([]interface{}); ok {
			for _, cert := range certPath {
				if certStr, ok := cert.(string); ok {
					sig.CertificatePath = append(sig.CertificatePath, certStr)
				}
			}
		}

		// Parse excludes
		if excludes, ok := sigMap["excludes"].([]interface{}); ok {
			for _, exclude := range excludes {
				if excludeStr, ok := exclude.(string); ok {
					sig.Excludes = append(sig.Excludes, excludeStr)
				}
			}
		}
	} else if signers, ok := sigMap["signers"].([]interface{}); ok && len(signers) > 0 {
		// Multiple signers format - use the first one
		if firstSigner, ok := signers[0].(map[string]interface{}); ok {
			sig = c.parseSignerMap(firstSigner)
		}
	} else if chain, ok := sigMap["chain"].([]interface{}); ok && len(chain) > 0 {
		// Certificate chain format - use the first one
		if firstSigner, ok := chain[0].(map[string]interface{}); ok {
			sig = c.parseSignerMap(firstSigner)
		}
	}

	if sig != nil {
		c.SignatureDetail = sig
		c.addToLogs("CyclonDX signature parsed")
	}
}

// parseSignerMap parses a signer object from a map
func (c *CdxDoc) parseSignerMap(signerMap map[string]interface{}) *Signature {
	sig := &Signature{}

	if algorithm, ok := signerMap["algorithm"].(string); ok {
		sig.Algorithm = algorithm
	}

	if keyID, ok := signerMap["keyId"].(string); ok {
		sig.KeyID = keyID
	}

	if value, ok := signerMap["value"].(string); ok {
		sig.SigValue = value
	}

	// Parse public key
	if pubKeyData, ok := signerMap["publicKey"].(map[string]interface{}); ok {
		sig.PublicKey = c.parsePublicKey(pubKeyData)
	}

	// Parse certificate path
	if certPath, ok := signerMap["certificatePath"].([]interface{}); ok {
		for _, cert := range certPath {
			if certStr, ok := cert.(string); ok {
				sig.CertificatePath = append(sig.CertificatePath, certStr)
			}
		}
	}

	// Parse excludes
	if excludes, ok := signerMap["excludes"].([]interface{}); ok {
		for _, exclude := range excludes {
			if excludeStr, ok := exclude.(string); ok {
				sig.Excludes = append(sig.Excludes, excludeStr)
			}
		}
	}

	return sig
}

// parsePublicKey parses a public key from the signature data
func (c *CdxDoc) parsePublicKey(pubKeyData map[string]interface{}) string {
	kty, _ := pubKeyData["kty"].(string)

	switch kty {
	case "RSA":
		n, _ := pubKeyData["n"].(string)
		e, _ := pubKeyData["e"].(string)
		if n != "" && e != "" {
			return c.convertRSAPublicKeyToPEM(n, e)
		}
	case "EC":
		crv, _ := pubKeyData["crv"].(string)
		x, _ := pubKeyData["x"].(string)
		y, _ := pubKeyData["y"].(string)
		if crv != "" && x != "" && y != "" {
			// For EC keys, store the raw key data for now
			// Full EC key conversion would require more complex handling
			return fmt.Sprintf("EC Key - Curve: %s", crv)
		}
	}

	return ""
}

// convertRSAPublicKeyToPEM converts RSA public key components to PEM format
func (c *CdxDoc) convertRSAPublicKeyToPEM(modulusB64, exponentB64 string) string {
	log := logger.FromContext(c.ctx)

	// Try URL-safe base64 decoding first, then standard
	modulus, err := base64.URLEncoding.DecodeString(modulusB64)
	if err != nil {
		// Try standard base64
		modulus, err = base64.StdEncoding.DecodeString(modulusB64)
		if err != nil {
			// Try raw URL encoding (no padding)
			modulus, err = base64.RawURLEncoding.DecodeString(modulusB64)
			if err != nil {
				log.Error("Error decoding public key modulus", zap.Error(err))
				return ""
			}
		}
	}

	// Decode the base64-encoded exponent
	exponentBytes, err := base64.URLEncoding.DecodeString(exponentB64)
	if err != nil {
		exponentBytes, err = base64.StdEncoding.DecodeString(exponentB64)
		if err != nil {
			exponentBytes, err = base64.RawURLEncoding.DecodeString(exponentB64)
			if err != nil {
				log.Error("Error decoding public key exponent", zap.Error(err))
				return ""
			}
		}
	}

	// Convert exponent bytes to integer
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}

	if exponent == 0 {
		c.addToLogs("Invalid public key exponent")
		return ""
	}

	// Create the RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: exponent,
	}

	// Convert to PEM format
	return string(publicKeyToPEM(pubKey))
}

func publicKeyToPEM(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return nil
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubPEM
}

func (c *CdxDoc) requiredFields() bool {
	if c.doc == nil {
		c.addToLogs("cdx doc is not parsable")
		return false
	}

	// This field is only required for JSON not for XML.
	if c.format == FileFormatJSON && c.doc.BOMFormat == "" {
		c.addToLogs("cdx doc is missing BOMFormat")
		return false
	}

	if c.doc.SpecVersion.String() == "" {
		c.addToLogs("cdx doc is missing specVersion")
		return false
	}

	if c.doc.Version < 1 {
		c.addToLogs("cdx doc is missing doc version")
		return false
	}

	if c.doc.Dependencies != nil {
		deps := lo.CountBy(lo.FromPtr(c.doc.Dependencies), func(d cydx.Dependency) bool {
			return d.Ref == ""
		})

		if deps > 0 {
			c.addToLogs("cdx doc is missing dependencies")
			return false
		}
	}
	return true
}

func copyC(cdxc *cydx.Component, c *CdxDoc) *Component {
	if cdxc == nil {
		return nil
	}

	nc := NewComponent()
	nc.Version = cdxc.Version
	nc.Name = cdxc.Name
	nc.Purpose = string(cdxc.Type)
	nc.isReqFieldsPresent = c.pkgRequiredFields(cdxc)
	nc.CopyRight = cdxc.Copyright
	ncpe := cpe.NewCPE(cdxc.CPE)
	if ncpe.Valid() {
		nc.Cpes = []cpe.CPE{ncpe}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid cpes found", cdxc.Name, -1))
	}

	npurl := purl.NewPURL(cdxc.PackageURL)
	if npurl.Valid() {
		nc.Purls = []purl.PURL{npurl}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid purl found", cdxc.Name, -1))
	}

	if cdxc.SWHID != nil {
		for _, swhidStr := range *cdxc.SWHID {
			nswhid := swhid.NewSWHID(swhidStr)
			if nswhid.Valid() {
				nc.Swhid = append(nc.Swhid, nswhid)
			} else {
				c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid swhid found", cdxc.Name, -1))
			}
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil SWHID", cdxc.Name))
	}

	if cdxc.SWID != nil {
		nswid := swid.NewSWID(cdxc.SWID.TagID, cdxc.SWID.Name)
		if nswid.Valid() {
			nc.Swid = []swid.SWID{nswid}
		} else {
			c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid swid found", cdxc.Name, -1))
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil SWID or SWID.Name", cdxc.Name))
	}

	if cdxc.OmniborID != nil {
		for _, omniStr := range *cdxc.OmniborID {
			omniID := omniborid.NewOmni(omniStr)
			if omniID.Valid() {
				nc.OmniID = append(nc.OmniID, omniID)
			} else {
				c.addToLogs(fmt.Sprintf("cdx base doc component %s at index %d invalid omniborid found", cdxc.Name, -1))
			}
		}
	} else {
		c.addToLogs(fmt.Sprintf("cdx base doc component %s has nil OmniborID", cdxc.Name))
	}

	nc.Checksums = c.checksums(cdxc)
	nc.Licenses = c.licenses(cdxc)
	nc.DeclaredLicense = c.declaredLicenses(cdxc)
	nc.ConcludedLicense = c.concludedLicenses(cdxc)

	supplier := c.assignSupplier(cdxc)
	if supplier != nil {
		nc.Supplier = *supplier
	}

	manufacturer := c.assignManufacturer(cdxc)
	if manufacturer != nil {
		nc.Manufacture = *manufacturer
	}

	authors := c.assignAuthor(cdxc)
	if authors != nil {
		nc.Athrs = authors
	}

	if cdxc.ExternalReferences != nil {
		sources := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeVCS
		})

		if len(sources) > 0 {
			nc.SourceCodeURL = sources[0].URL
		}

		downloads := lo.Filter(*cdxc.ExternalReferences, func(er cydx.ExternalReference, _ int) bool {
			return er.Type == cydx.ERTypeDistribution || er.Type == cydx.ERTypeDistributionIntake
		})

		if len(downloads) > 0 {
			nc.DownloadLocation = downloads[0].URL
		}
	}

	nc.ID = cdxc.BOMRef

	// For CycloneDX 1.6+, licenses have an acknowledgement field to distinguish
	// declared vs concluded. When acknowledgement is not specified but licenses exist,
	// default to declared for 1.6+ (as per spec), and concluded for earlier versions.
	if len(nc.Licenses) > 0 && len(nc.DeclaredLicense) == 0 && len(nc.ConcludedLicense) == 0 {
		if isCdxSpecVersionAtLeast(c.doc.SpecVersion.String(), "1.6") {
			nc.DeclaredLicense = nc.Licenses
		} else {
			nc.ConcludedLicense = nc.Licenses
		}
	}

	return nc
}

func (c *CdxDoc) parseComps() {
	comps := map[string]*Component{}
	if c.doc.Metadata != nil && c.doc.Metadata.Component != nil {
		walkComponents(&[]cydx.Component{*c.doc.Metadata.Component}, c, comps)
	}

	if c.doc.Components != nil {
		walkComponents(c.doc.Components, c, comps)
	}

	c.Comps = make([]GetComponent, 0, len(comps))
	for _, v := range comps {
		c.Comps = append(c.Comps, v)
	}
}

func walkComponents(comps *[]cydx.Component, doc *CdxDoc, store map[string]*Component) {
	if comps == nil {
		return
	}
	for _, c := range *comps {
		if c.Components != nil {
			walkComponents(c.Components, doc, store)
		}
		//nolint:gosec
		if _, ok := store[compID(&c)]; ok {
			// already present no need to re add it.
			continue
		}
		//nolint:gosec
		store[compID(&c)] = copyC(&c, doc)
	}
}

func compID(comp *cydx.Component) string {
	if comp.BOMRef != "" {
		return comp.BOMRef
	}

	if comp.PackageURL != "" {
		return comp.PackageURL
	}

	// A component with no BOMREF or PackageURL is a bad component, so we generate a UUID for it.
	// This is a temporary solution until we can figure out how to handle this case.
	id := uuid.New()
	return id.String()
}

func (c *CdxDoc) pkgRequiredFields(comp *cydx.Component) bool {
	if string(comp.Type) == "" {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s missing type field", comp.Name))
		return false
	}

	if comp.Name == "" {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s missing type field", comp.BOMRef))
		return false
	}

	return true
}

func (c *CdxDoc) checksums(comp *cydx.Component) []GetChecksum {
	hashes := lo.FromPtr(comp.Hashes)
	if len(hashes) == 0 {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no checksum found", comp.Name))
		return []GetChecksum{}
	}

	chks := make([]GetChecksum, 0, len(hashes))
	for _, cl := range hashes {
		ck := Checksum{}
		ck.Alg = string(cl.Algorithm)
		ck.Content = cl.Value
		chks = append(chks, ck)
	}
	return chks
}

func (c *CdxDoc) licenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "")
}

func (c *CdxDoc) declaredLicenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "declared")
}

func (c *CdxDoc) concludedLicenses(comp *cydx.Component) []licenses.License {
	return aggregateLicenses(lo.FromPtr(comp.Licenses), "concluded")
}

func aggregateLicenses(clicenses cydx.Licenses, filter string) []licenses.License {
	if clicenses == nil {
		return []licenses.License{}
	}

	lics := make([]licenses.License, 0, len(clicenses))

	getLicenses := func(exp string) []licenses.License {
		return licenses.LookupExpression(exp, []licenses.License{})
	}

	for _, cl := range clicenses {
		if filter == "" && cl.Expression != "" {
			lics = append(lics, getLicenses(cl.Expression)...)
		} else if cl.License != nil {
			if filter == "" || string(cl.License.Acknowledgement) == filter {
				if cl.License.ID != "" {
					lics = append(lics, getLicenses(cl.License.ID)...)
				} else if cl.License.Name != "" {
					lics = append(lics, getLicenses(cl.License.Name)...)
				}
			}
		}
	}

	return lics
}

func (c *CdxDoc) parseTool() {
	if c.doc.Metadata == nil {
		return
	}

	if c.doc.Metadata.Tools == nil {
		return
	}

	// Calculate capacity based on all tool sources
	tools := lo.FromPtr(c.doc.Metadata.Tools.Tools)
	components := lo.FromPtr(c.doc.Metadata.Tools.Components)
	services := lo.FromPtr(c.doc.Metadata.Tools.Services)
	totalCapacity := len(tools) + len(components) + len(services)

	c.CdxTools = make([]GetTool, 0, totalCapacity)

	for _, tt := range tools {
		t := Tool{}
		t.Name = tt.Name
		t.Version = tt.Version
		c.CdxTools = append(c.CdxTools, t)
	}

	for _, ct := range components {
		t := Tool{}
		t.Name = ct.Name
		t.Version = ct.Version
		c.CdxTools = append(c.CdxTools, t)
	}

	for _, ct := range services {
		t := Tool{}
		t.Name = ct.Name
		t.Version = ct.Version
		c.CdxTools = append(c.CdxTools, t)
	}
}

func (c *CdxDoc) parseAuthors() {
	if c.doc.Metadata == nil {
		return
	}

	authors := lo.FromPtr(c.doc.Metadata.Authors)
	c.CdxAuthors = make([]GetAuthor, 0, len(authors))

	for _, auth := range authors {
		a := Author{}
		a.Name = auth.Name
		a.Email = auth.Email
		a.Phone = auth.Phone
		a.AuthorType = "person"
		c.CdxAuthors = append(c.CdxAuthors, a)
	}
}

func (c *CdxDoc) parseSupplier() {
	// Early return if required nested fields are nil
	if c.doc.Metadata == nil || c.doc.Metadata.Supplier == nil {
		return
	}

	// Initialize supplier with known fields
	supplier := Supplier{
		Name: c.doc.Metadata.Supplier.Name,
	}

	// Safely handle URL
	if urls := lo.FromPtr(c.doc.Metadata.Supplier.URL); len(urls) > 0 {
		supplier.URL = urls[0]
	}

	// Handle contacts array
	if c.doc.Metadata.Supplier.Contact != nil {
		contacts := lo.FromPtr(c.doc.Metadata.Supplier.Contact)
		if len(contacts) > 0 {
			// Pre-allocate contacts slice with known capacity
			supplier.Contacts = make([]Contact, 0, len(contacts))

			// Process each contact
			for _, cydxContact := range contacts {
				supplier.Contacts = append(supplier.Contacts, Contact{
					Name:  cydxContact.Name,
					Email: cydxContact.Email,
				})
			}
		}
	}

	c.CdxSupplier = supplier
}

func (c *CdxDoc) parseManufacturer() {
	if c.doc.Metadata == nil || c.doc.Metadata.Manufacture == nil {
		return
	}

	manufacturer := Manufacturer{Name: c.doc.Metadata.Manufacture.Name}

	if urls := lo.FromPtr(c.doc.Metadata.Manufacture.URL); len(urls) > 0 {
		manufacturer.URL = urls[0]
	}

	contacts := lo.FromPtr(c.doc.Metadata.Manufacture.Contact)
	if len(contacts) > 0 {
		manufacturer.Contacts = make([]Contact, len(contacts))
		for i, contact := range contacts {
			manufacturer.Contacts[i] = Contact{
				Name:  contact.Name,
				Email: contact.Email,
			}
		}
	}

	c.CdxManufacturer = manufacturer
}

func (c *CdxDoc) parsePrimaryComponent() {
	if c.doc.Metadata == nil || c.doc.Metadata.Component == nil {
		return
	}

	comp := c.doc.Metadata.Component

	if strings.TrimSpace(comp.BOMRef) == "" {
		return
	}

	c.PrimaryComponent = PrimaryComponentInfo{
		ID:      comp.BOMRef,
		Name:    comp.Name,
		Version: comp.Version,
		Type:    string(comp.Type),
		Present: true,
	}
}

func (c *CdxDoc) parseDependencies() {
	c.Relationships = []GetRelationship{}

	for _, d := range lo.FromPtr(c.doc.Dependencies) {
		from := d.Ref
		for _, to := range lo.FromPtr(d.Dependencies) {
			rel := Relationship{
				From: from,
				To:   to,
				Type: "DEPENDS_ON",
			}
			c.Relationships = append(c.Relationships, rel)
		}
	}
}

func (c *CdxDoc) assignAuthor(comp *cydx.Component) []GetAuthor {
	// 1) If cdx:1.6, with `authors` are present, use them
	if comp.Authors != nil && len(*comp.Authors) > 0 {
		out := make([]GetAuthor, 0, len(*comp.Authors))
		for _, a := range *comp.Authors {
			au := Author{
				Name:  a.Name,
				Email: a.Email,
				Phone: a.Phone,
				// AuthorType: a.Type, // map fields as appropriate
			}
			out = append(out, au)
		}
		return out
	}

	// 2) Fallback: parse legacy `author` string (could be "Name <email>" or list)
	//    i.e `author`
	if comp.Author == "" {
		// no authors present in either form
		return nil
	}

	authorStr := comp.Author

	// ParseAddressList handles comma-separated lists and quoted names.
	addrs, err := mail.ParseAddressList(authorStr)
	if err != nil {
		if a, perr := mail.ParseAddress(authorStr); perr == nil {
			addrs = []*mail.Address{a}
		} else {
			c.addToLogs(fmt.Sprintf("assignAuthor: cannot parse author string %q: %v", authorStr, err))
			return []GetAuthor{Author{Name: authorStr}}
		}
	}

	out := make([]GetAuthor, 0, len(addrs))
	for _, addr := range addrs {
		au := Author{
			Name:  addr.Name,
			Email: addr.Address,
		}
		out = append(out, au)
	}
	return out
}

func (c *CdxDoc) assignSupplier(comp *cydx.Component) *Supplier {
	if comp.Supplier == nil {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no supplier found", comp.Name))
		return nil
	}

	supplier := Supplier{Name: comp.Supplier.Name}

	if urls := lo.FromPtr(comp.Supplier.URL); len(urls) > 0 {
		supplier.URL = urls[0]
	}

	contacts := lo.FromPtr(comp.Supplier.Contact)
	if len(contacts) > 0 {
		supplier.Contacts = make([]Contact, len(contacts))
		for i, contact := range contacts {
			supplier.Contacts[i] = Contact{
				Name:  contact.Name,
				Email: contact.Email,
			}
		}
	}

	return &supplier
}

func (c *CdxDoc) assignManufacturer(comp *cydx.Component) *Manufacturer {
	if comp.Manufacturer == nil {
		c.addToLogs(fmt.Sprintf("cdx doc comp %s no manufacturer found", comp.Name))
		return nil
	}

	manufacturer := Manufacturer{Name: comp.Manufacturer.Name}

	if urls := lo.FromPtr(comp.Manufacturer.URL); len(urls) > 0 {
		manufacturer.URL = urls[0]
	}

	contacts := lo.FromPtr(comp.Manufacturer.Contact)
	if len(contacts) > 0 {
		manufacturer.Contacts = make([]Contact, len(contacts))
		for i, contact := range contacts {
			manufacturer.Contacts[i] = Contact{
				Name:  contact.Name,
				Email: contact.Email,
			}
		}
	}

	return &manufacturer
}

func (c *CdxDoc) parseCompositions() {
	if c.doc == nil || c.doc.Compositions == nil {
		return
	}

	for _, cdxc := range *c.doc.Compositions {
		agg := CompositionAggregate(cdxc.Aggregate)

		scope := ScopeGlobal
		switch {
		case cdxc.Dependencies != nil && len(*cdxc.Dependencies) > 0:
			scope = ScopeDependencies
		case cdxc.Assemblies != nil && len(*cdxc.Assemblies) > 0:
			scope = ScopeAssemblies
		case cdxc.Vulnerabilities != nil && len(*cdxc.Vulnerabilities) > 0:
			scope = ScopeVulnerabilities
		}

		comp := Composition{
			id:        cdxc.BOMRef,
			scope:     scope,
			aggregate: agg,
		}

		if cdxc.Dependencies != nil {
			for _, dep := range *cdxc.Dependencies {
				comp.dependencies = append(comp.dependencies, string(dep))
			}
		}

		if cdxc.Assemblies != nil {
			for _, asm := range *cdxc.Assemblies {
				comp.assemblies = append(comp.assemblies, string(asm))
			}
		}

		if cdxc.Vulnerabilities != nil {
			for _, v := range *cdxc.Vulnerabilities {
				comp.vulnerabilities = append(comp.vulnerabilities, string(v))
			}
		}

		c.Compositions = append(c.Compositions, comp)
	}
}

// isCdxSpecVersionAtLeast returns true if the given specVersion is at least the minVersion.
// Both versions are expected in the format "X.Y" (e.g., "1.6").
func isCdxSpecVersionAtLeast(specVersion, minVersion string) bool {
	parseVersion := func(v string) (int, int) {
		parts := strings.Split(v, ".")
		if len(parts) != 2 {
			return 0, 0
		}
		major, minor := 0, 0
		fmt.Sscanf(parts[0], "%d", &major)
		fmt.Sscanf(parts[1], "%d", &minor)
		return major, minor
	}

	specMajor, specMinor := parseVersion(specVersion)
	minMajor, minMinor := parseVersion(minVersion)

	if specMajor > minMajor {
		return true
	}
	if specMajor == minMajor && specMinor >= minMinor {
		return true
	}
	return false
}
