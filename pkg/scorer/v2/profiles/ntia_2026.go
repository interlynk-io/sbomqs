// Copyright 2026 Interlynk.io
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

package profiles

import (
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// NTIA 2026 minimum version requirements.
const (
	ntia2026MinCDX  = "1.4"
	ntia2026MinSPDX = "2.3"
)

// NTIA2026SBOMDataFormat checks that the SBOM data format is declared (SPDX or CycloneDX)
// and that the file format (JSON/XML/Tag-Value) is present.
func NTIA2026SBOMDataFormat(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))

	if spec == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM data format is not declared",
		}
	}

	if format == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM file format (JSON/XML/Tag-Value) is not declared",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc:  "CycloneDX is declared SBOM data format",
		}
	case string(sbom.SBOMSpecSPDX):
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc:  "SPDX is declared SBOM data format",
		}
	}

	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  fmt.Sprintf("unsupported spec type: %s", spec),
	}
}

// NTIA2026SBOMSpecVersion checks whether the SBOM's specification version is present
// and meets CISA 2026 minimum requirements (CycloneDX >= 1.4, SPDX >= 2.3).
func NTIA2026SBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	ver := strings.TrimSpace(doc.Spec().GetVersion())
	if ver == "" || ver == "SpecVersion(0)" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM specification version is not declared",
			Ignore: false,
		}
	}

	var format, minVer string
	switch doc.Spec().GetSpecType() {
	case string(sbom.SBOMSpecCDX):
		format = "CycloneDX"
		minVer = ntia2026MinCDX
	case string(sbom.SBOMSpecSPDX):
		format = "SPDX"
		minVer = ntia2026MinSPDX
	}

	if minVer != "" && isVersionAtLeast(ver, minVer) {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   fmt.Sprintf("%s %s meets minimum version %s", format, ver, minVer),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   fmt.Sprintf("%s %s does not meet minimum version %s", format, ver, minVer),
		Ignore: false,
	}
}

// NTIA2026SBOMToolName checks whether the tool that generated the SBOM has a name.
// CISA 2026 requires tool name information.
func NTIA2026SBOMToolName(doc sbom.Document) catalog.ProfFeatScore {
	tools := doc.Tools()
	if len(tools) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM generation tool is not declared",
			Ignore: false,
		}
	}

	for _, tool := range tools {
		name := strings.TrimSpace(tool.GetName())
		if name != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   fmt.Sprintf("SBOM generation tool name (%s) is declared", name),
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM generation tool is present but name is missing",
		Ignore: false,
	}
}

// NTIA2026SBOMToolVersion checks whether the tool that generated the SBOM has a version.
// CISA 2026 requires tool version information (not just name).
func NTIA2026SBOMToolVersion(doc sbom.Document) catalog.ProfFeatScore {
	tools := doc.Tools()
	if len(tools) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM generation tool is not declared",
			Ignore: false,
		}
	}

	for _, tool := range tools {
		ver := strings.TrimSpace(tool.GetVersion())
		if ver != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   fmt.Sprintf("SBOM generation tool version (%s) is declared", ver),
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM generation tool name is present but version is missing",
		Ignore: false,
	}
}

// NTIA2026SBOMVersion checks whether the SBOM document itself has a version identifier.
// For CycloneDX: checks Spec.GetURI() which returns urn:uuid:{serialNumber}/{version}
// For SPDX: author-assigned SBOM version is not supported by the spec → N/A
func NTIA2026SBOMVersion(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == string(sbom.SBOMSpecCDX) {
		uri := strings.TrimSpace(doc.Spec().GetURI())
		parts := strings.Split(uri, "/")
		if len(parts) >= 2 && strings.TrimSpace(parts[len(parts)-1]) != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM document version is declared via serialNumber and version",
				Ignore: false,
			}
		}
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM document version (serialNumber and version) is not declared",
			Ignore: false,
		}
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "SPDX does not support author-assigned SBOM document versions",
			Ignore: true,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown spec; cannot determine SBOM version support",
		Ignore: false,
	}
}

// NTIA2026SBOMCreationTimestamp checks whether the SBOM has a valid creation timestamp.
// CISA 2026 requires the timestamp to be valid and RFC 9557-compliant.
func NTIA2026SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creation timestamp is not declared",
			Ignore: false,
		}
	}

	// accept both RFC3339 and RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   fmt.Sprintf("SBOM creation timestamp (%s) is invalid", ts),
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "SBOM creation timestamp is valid and RFC 9557-compliant",
		Ignore: false,
	}
}

// NTIA2026GenerationContext checks whether the SBOM includes context for how it was generated.
// For CycloneDX: checks Lifecycles (metadata.lifecycles)
// For SPDX v2.x: checks CreationInfo.Comment (document-level comment)
// For SPDX 3.x: checks Lifecycles (software_Sbom.sbomType or CreationInfo.Comment)
func NTIA2026GenerationContext(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == string(sbom.SBOMSpecCDX) {
		lifecycles := doc.Lifecycles()
		if len(lifecycles) > 0 {
			phases := make([]string, 0, len(lifecycles))
			for _, p := range lifecycles {
				if p != "" {
					phases = append(phases, p)
				}
			}
			if len(phases) > 0 {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   fmt.Sprintf("SBOM generation context is %s phase", strings.Join(phases, ", ")),
					Ignore: false,
				}
			}
		}
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM generation context (lifecycle phase) is not declared",
			Ignore: false,
		}
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		if strings.HasPrefix(ver, "3.") {
			lifecycles := doc.Lifecycles()
			if len(lifecycles) > 0 {
				phases := make([]string, 0, len(lifecycles))
				for _, p := range lifecycles {
					if p != "" {
						phases = append(phases, p)
					}
				}
				if len(phases) > 0 {
					return catalog.ProfFeatScore{
						Score:  10.0,
						Desc:   fmt.Sprintf("SBOM generation context is %s phase", strings.Join(phases, ", ")),
						Ignore: false,
					}
				}
			}
			comment := strings.TrimSpace(doc.Spec().GetComment())
			if comment != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "SBOM generation context is declared via creationInfo.comment",
					Ignore: false,
				}
			}
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "SBOM generation context (lifecycle or creationInfo.comment) is not declared",
				Ignore: false,
			}
		}

		comment := strings.TrimSpace(doc.Spec().GetComment())
		if comment != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "SBOM generation context is declared via creationInfo.comment",
				Ignore: false,
			}
		}
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM generation context (creationInfo.comment) is not declared",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown spec; cannot determine generation context",
		Ignore: false,
	}
}

// NTIA2026SBOMAuthors checks whether the SBOM has a person or organization as author.
// CISA 2026 explicitly requires the SBOM Author to be a person or organization;
// tool entries are NOT accepted.
func NTIA2026SBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	authors := doc.Authors()
	var legalAuthors []sbom.GetAuthor

	for _, author := range authors {
		authType := strings.ToLower(strings.TrimSpace(author.GetType()))
		// Explicitly reject tool entries per CISA 2026 guidance
		if authType == "tool" {
			continue
		}
		if strings.TrimSpace(author.GetName()) != "" || strings.TrimSpace(author.GetEmail()) != "" || strings.TrimSpace(author.GetURL()) != "" {
			legalAuthors = append(legalAuthors, author)
		}
	}

	if len(legalAuthors) > 0 {
		// Build detail from first legal author: priority name > email > URL
		first := legalAuthors[0]
		name := strings.TrimSpace(first.GetName())
		email := strings.TrimSpace(first.GetEmail())
		url := strings.TrimSpace(first.GetURL())

		detail := ""
		if name != "" {
			detail = name
		} else if email != "" {
			detail = email
		} else if url != "" {
			detail = url
		}

		if detail != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   fmt.Sprintf("SBOM creator (%s) provided via authors", detail),
				Ignore: false,
			}
		}

		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   fmt.Sprintf("SBOM author(s) declared by %d person(s) / organization(s)", len(legalAuthors)),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "SBOM author (person or organization) is missing; tool entries are not accepted",
		Ignore: false,
	}
}

// NTIA2026SBOMRelationships checks whether the SBOM has dependency relationships
// for the primary component.
func NTIA2026SBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
	var have int

	primary := doc.PrimaryComp()
	if primary.IsPresent() {
		have = len(doc.GetDirectDependencies(primary.GetID()))
	}

	if have == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM dependency relationships are not declared",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("SBOM dependency relationships declared for %d direct dependencies", have),
		Ignore: false,
	}
}

// NTIA2026SBOMSignature checks whether the SBOM has a digital signature.
func NTIA2026SBOMSignature(doc sbom.Document) catalog.ProfFeatScore {
	sig := doc.Signature()
	if sig == nil {
		spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
		ver := strings.TrimSpace(doc.Spec().GetVersion())
		if spec == string(sbom.SBOMSpecSPDX) && !strings.HasPrefix(ver, "3.") {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "SPDX versions below 3.0 do not support signatures",
				Ignore: true,
			}
		}
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM digital signature is not declared",
			Ignore: false,
		}
	}

	algorithm := strings.TrimSpace(sig.GetAlgorithm())
	sigValue := strings.TrimSpace(sig.GetSigValue())

	if algorithm == "" || sigValue == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM signature is present but incomplete (algorithm or value missing)",
			Ignore: false,
		}
	}

	pubKey := strings.TrimSpace(sig.GetPublicKey())
	certPath := sig.GetCertificatePath()

	if pubKey == "" && len(certPath) == 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   fmt.Sprintf("SBOM digital signature (%s) is declared", algorithm),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   fmt.Sprintf("SBOM digital signature (%s) with verification material is declared", algorithm),
		Ignore: false,
	}
}

// ── Component-level evaluators with BSI-style ratio descriptions ──

// ntia2026ComponentScore builds BSI-style descriptions for component-level fields.
func ntia2026ComponentScore(valid, total int, fieldLabel string) catalog.ProfFeatScore {
	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}
	if valid == total {
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc:  fmt.Sprintf("%s declared for all components", fieldLabel),
		}
	}
	if valid > 0 {
		return catalog.ProfFeatScore{
			Score: float64(valid) / float64(total) * 10.0,
			Desc:  fmt.Sprintf("%d/%d components declare %s", valid, total, fieldLabel),
		}
	}
	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  fmt.Sprintf("no components declare %s", fieldLabel),
	}
}

// NTIA2026CompName checks that all components have a name.
func NTIA2026CompName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})
	return ntia2026ComponentScore(valid, len(comps), "name")
}

// NTIA2026CompVersion checks that all components have a version.
func NTIA2026CompVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})
	return ntia2026ComponentScore(valid, len(comps), "version")
}

// NTIA2026CompUniqID checks that all components have a unique identifier (PURL, CPE, or SWID).
func NTIA2026CompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		if common.CompHasAnyPURLs(c) {
			return true
		}
		if common.CompHasAnyCPEs(c) {
			return true
		}
		if len(c.Swids()) > 0 {
			return true
		}
		return false
	})
	return ntia2026ComponentScore(valid, len(comps), "unique identifier")
}

// NTIA2026CompProducer checks whether each component has producer information.
// CISA 2026 uses "Component Producer" (formerly Supplier Name) and evaluates it
// per-component using Suppliers, Manufacturer, or Authors.
func NTIA2026CompProducer(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := 0
	for _, c := range comps {
		found := false
		if supplier := c.Suppliers(); supplier != nil {
			if strings.TrimSpace(supplier.GetName()) != "" ||
				strings.TrimSpace(supplier.GetEmail()) != "" ||
				strings.TrimSpace(supplier.GetURL()) != "" {
				valid++
				found = true
			}
		}
		if found {
			continue
		}
		if manufacturer := c.Manufacturer(); manufacturer != nil {
			if strings.TrimSpace(manufacturer.GetName()) != "" ||
				strings.TrimSpace(manufacturer.GetEmail()) != "" ||
				strings.TrimSpace(manufacturer.GetURL()) != "" {
				valid++
				found = true
			}
		}
		if found {
			continue
		}
		for _, author := range c.Authors() {
			if strings.TrimSpace(author.GetName()) != "" || strings.TrimSpace(author.GetEmail()) != "" {
				valid++
				break
			}
		}
	}
	return ntia2026ComponentScore(valid, len(comps), "producer")
}

// NTIA2026CompHashValue checks whether each component has at least one checksum value.
// CISA 2026 requires component-level hash values.
func NTIA2026CompHashValue(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		checksums := c.GetChecksums()
		if len(checksums) == 0 {
			return false
		}
		for _, checksum := range checksums {
			if strings.TrimSpace(checksum.GetContent()) != "" {
				return true
			}
		}
		return false
	})
	return ntia2026ComponentScore(valid, len(comps), "hash value")
}

// NTIA2026CompHashAlgo checks whether each component has at least one checksum algorithm.
// CISA 2026 requires component-level hashes with algorithm specified.
func NTIA2026CompHashAlgo(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		checksums := c.GetChecksums()
		if len(checksums) == 0 {
			return false
		}
		for _, checksum := range checksums {
			if strings.TrimSpace(checksum.GetAlgo()) != "" {
				return true
			}
		}
		return false
	})
	return ntia2026ComponentScore(valid, len(comps), "hash algorithm")
}

// NTIA2026CompLicense checks that all components have a declared license.
func NTIA2026CompLicense(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return common.ComponentHasAnyDeclared(c)
	})
	return ntia2026ComponentScore(valid, len(comps), "declared license")
}
