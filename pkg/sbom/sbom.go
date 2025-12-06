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

// Package sbom provides core SBOM (Software Bill of Materials) parsing, processing,
// and manipulation functionality for handling SPDX and CycloneDX format documents.
package sbom

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"gopkg.in/yaml.v2"
)

// SpecFormat represents the SBOM specification format type (SPDX, CycloneDX, etc.)
type SpecFormat string

const (
	// SBOMSpecSPDX represents the SPDX SBOM specification format
	SBOMSpecSPDX    SpecFormat = "spdx"
	// SBOMSpecCDX represents the CycloneDX SBOM specification format
	SBOMSpecCDX     SpecFormat = "cyclonedx"
	// SBOMSpecUnknown represents an unknown or unsupported SBOM specification format
	SBOMSpecUnknown SpecFormat = "unknown"
)

type (
	// FileFormat represents the file encoding format of an SBOM (JSON, XML, YAML, etc.)
	FileFormat    string
	// FormatVersion represents the version string of an SBOM specification
	FormatVersion string
)

const (
	// FileFormatJSON represents JSON file format
	FileFormatJSON     FileFormat = "json"
	// FileFormatRDF represents RDF file format
	FileFormatRDF      FileFormat = "rdf"
	// FileFormatYAML represents YAML file format
	FileFormatYAML     FileFormat = "yaml"
	// FileFormatTagValue represents SPDX tag-value file format
	FileFormatTagValue FileFormat = "tag-value"
	// FileFormatXML represents XML file format
	FileFormatXML      FileFormat = "xml"
	// FileFormatUnknown represents an unknown or unsupported file format
	FileFormatUnknown  FileFormat = "unknown"
)

type spdxbasic struct {
	ID      string `json:"SPDXID" yaml:"SPDXID"`
	Version string `json:"spdxVersion" yaml:"spdxVersion"`
}

// spdx3basic represents the basic structure of SPDX 3.0/3.0.1 documents
type spdx3basic struct {
	Context      interface{} `json:"@context"`
	Graph        []map[string]interface{} `json:"@graph,omitempty"`
	SpdxId       string `json:"spdxId,omitempty"`
	Type         interface{} `json:"type,omitempty"`
	CreationInfo map[string]interface{} `json:"creationInfo,omitempty"`
}

type cdxbasic struct {
	XMLNS     string `json:"-" xml:"xmlns,attr"`
	BOMFormat string `json:"bomFormat" xml:"-"`
}

// SupportedSBOMSpecs returns a list of all supported SBOM specification formats
func SupportedSBOMSpecs() []string {
	return []string{string(SBOMSpecSPDX), string(SBOMSpecCDX)}
}

// SupportedSBOMSpecVersions returns a list of supported versions for the given SBOM specification format
func SupportedSBOMSpecVersions(f string) []string {
	switch strings.ToLower(f) {
	case string(SBOMSpecCDX):
		return cdxSpecVersions
	case string(SBOMSpecSPDX):
		return spdxSpecVersions
	default:
		return []string{}
	}
}

// SupportedSBOMFileFormats returns a list of supported file formats for the given SBOM specification
func SupportedSBOMFileFormats(f string) []string {
	switch strings.ToLower(f) {
	case string(SBOMSpecCDX):
		return cdxFileFormats
	case string(SBOMSpecSPDX):
		return spdxFileFormats
	default:
		return []string{}
	}
}

// SupportedPrimaryPurpose returns a list of supported primary purpose values for the given SBOM specification
func SupportedPrimaryPurpose(f string) []string {
	switch strings.ToLower(f) {
	case "cyclonedx":
		return cdxPrimaryPurpose
	case "spdx":
		return spdxPrimaryPurpose
	default:
		return []string{}
	}
}

func detectSbomFormat(f io.ReadSeeker) (SpecFormat, FileFormat, FormatVersion, error) {
	defer func() {
		_, err := f.Seek(0, io.SeekStart)
		if err != nil {
			log.Printf("Failed to seek: %v", err)
		}
	}()

	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		log.Fatalf("Failed to seek: %v", err)
	}

	// Check for SPDX 3.0/3.0.1 first (JSON-LD format)
	var s3 spdx3basic
	if err := json.NewDecoder(f).Decode(&s3); err == nil {
		// Check if it's SPDX 3.0 or 3.0.1 by examining the @context field
		// Context can be a string or an array of strings
		contextStr := ""
		switch ctx := s3.Context.(type) {
		case string:
			contextStr = ctx
		case []interface{}:
			// If it's an array, check the first element
			if len(ctx) > 0 {
				if s, ok := ctx[0].(string); ok {
					contextStr = s
				}
			}
		}
		
		if contextStr != "" {
			// Check for SPDX 3.0.1 (handles both .json and .jsonld extensions)
			if strings.Contains(contextStr, "spdx.org/rdf/3.0.1/") {
				// Extract version from CreationInfo if available
				if s3.CreationInfo != nil {
					if specVersion, ok := s3.CreationInfo["specVersion"].(string); ok {
						return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-" + specVersion), nil
					}
				}
				return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-3.0.1"), nil
			} else if strings.Contains(contextStr, "spdx.org/rdf/3.0/") {
				// Extract version from CreationInfo if available
				if s3.CreationInfo != nil {
					if specVersion, ok := s3.CreationInfo["specVersion"].(string); ok {
						return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-" + specVersion), nil
					}
				}
				return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-3.0"), nil
			}
		}
		
		// Also check for @graph structure which indicates SPDX 3.x
		if s3.Graph != nil && len(s3.Graph) > 0 {
			// Try to find version info in graph elements
			for _, elem := range s3.Graph {
				if creationInfo, ok := elem["creationInfo"].(map[string]interface{}); ok {
					if specVersion, ok := creationInfo["specVersion"].(string); ok {
						return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-" + specVersion), nil
					}
				}
			}
			// If we have a @graph but no version info, assume 3.0.1 (latest)
			return SBOMSpecSPDX, FileFormatJSON, FormatVersion("SPDX-3.0.1"), nil
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	// Check for SPDX 2.x
	var s spdxbasic
	if err := json.NewDecoder(f).Decode(&s); err == nil {
		if strings.HasPrefix(s.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatJSON, FormatVersion(s.Version), nil
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	var cdx cdxbasic
	if err := json.NewDecoder(f).Decode(&cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			return SBOMSpecCDX, FileFormatJSON, "", nil
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	if err := xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, "", nil
		}
	}
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	if sc := bufio.NewScanner(f); sc.Scan() {
		if strings.HasPrefix(sc.Text(), "SPDX") {
			return SBOMSpecSPDX, FileFormatTagValue, "", nil
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	var y spdxbasic
	if err := yaml.NewDecoder(f).Decode(&y); err == nil {
		if strings.HasPrefix(y.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatYAML, FormatVersion(s.Version), nil
		}
	}

	return SBOMSpecUnknown, FileFormatUnknown, "", nil
}

// NewSBOMDocument creates a new SBOM document from the provided reader, automatically detecting the format and specification
func NewSBOMDocument(ctx context.Context, f io.ReadSeeker, sig Signature) (Document, error) {
	log := logger.FromContext(ctx)

	spec, format, version, err := detectSbomFormat(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("SBOM detect spec:%s version:%s format:%s ", spec, version, format)

	var doc Document

	switch spec {
	case SBOMSpecSPDX:
		doc, err = newSPDXDoc(ctx, f, format, version, sig)
	case SBOMSpecCDX:
		doc, err = newCDXDoc(ctx, f, format, sig)
	default:
		return nil, errors.New("unsupported sbom format")
	}

	return doc, err
}
