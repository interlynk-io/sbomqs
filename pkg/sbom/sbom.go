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
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// SpecFormat represents the SBOM specification format type (SPDX, CycloneDX, etc.)
type SpecFormat string

const (
	// SBOMSpecSPDX represents the SPDX SBOM specification format
	SBOMSpecSPDX SpecFormat = "spdx"
	// SBOMSpecCDX represents the CycloneDX SBOM specification format
	SBOMSpecCDX SpecFormat = "cyclonedx"
	// SBOMSpecUnknown represents an unknown or unsupported SBOM specification format
	SBOMSpecUnknown SpecFormat = "unknown"
)

type (
	// FileFormat represents the file encoding format of an SBOM (JSON, XML, YAML, etc.)
	FileFormat string
	// FormatVersion represents the version string of an SBOM specification
	FormatVersion string
)

const (
	// FileFormatJSON represents JSON file format
	FileFormatJSON FileFormat = "json"
	// FileFormatRDF represents RDF file format
	FileFormatRDF FileFormat = "rdf"
	// FileFormatYAML represents YAML file format
	FileFormatYAML FileFormat = "yaml"
	// FileFormatTagValue represents SPDX tag-value file format
	FileFormatTagValue FileFormat = "tag-value"
	// FileFormatXML represents XML file format
	FileFormatXML FileFormat = "xml"
	// FileFormatUnknown represents an unknown or unsupported file format
	FileFormatUnknown FileFormat = "unknown"
)

type spdxbasic struct {
	ID      string `json:"SPDXID" yaml:"SPDXID"`
	Version string `json:"spdxVersion" yaml:"spdxVersion"`
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

	log.Debug("Detecting SBOM format")
	spec, format, version, err := detectSbomFormat(f)
	if err != nil {
		log.Error("Failed to detect SBOM format",
			zap.Error(err),
		)
		return nil, err
	}

	log.Info("Detected SBOM",
		zap.String("spec", string(spec)),
		zap.String("format", string(format)),
		zap.String("version", string(version)),
	)

	var doc Document

	switch spec {
	case SBOMSpecSPDX:
		log.Debug("Initializing SPDX document parser",
			zap.String("format", string(format)),
			zap.String("version", string(version)),
		)
		doc, err = newSPDXDoc(ctx, f, format, version, sig)

	case SBOMSpecCDX:
		log.Debug("Initializing CycloneDX document parser",
			zap.String("format", string(format)),
		)
		doc, err = newCDXDoc(ctx, f, format, sig)

	default:
		log.Error("Unsupported SBOM specification",
			zap.String("spec", string(spec)),
		)
		return nil, errors.New("unsupported sbom format")
	}

	if err != nil {
		log.Error("Failed to parse SBOM document",
			zap.String("spec", string(spec)),
			zap.String("format", string(format)),
			zap.String("version", string(version)),
			zap.Error(err),
		)
		return nil, err
	}

	log.Debug("SBOM document parsed",
		zap.String("spec", string(spec)),
		zap.String("format", string(format)),
		zap.String("version", string(version)),
	)

	return doc, nil
}

func NewSBOMDocumentFromBytes(ctx context.Context, b []byte, sig Signature) (Document, error) {
	log := logger.FromContext(ctx)

	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("empty SBOM input")
	}

	// Wrap bytes so we can reuse existing logic
	r := bytes.NewReader(b)

	log.Debug("Detecting SBOM format from bytes")
	spec, format, version, err := detectSbomFormat(r)
	if err != nil {
		log.Error("Failed to detect SBOM format from bytes",
			zap.Error(err),
		)
		return nil, err
	}

	log.Info("Detected SBOM",
		zap.String("spec", string(spec)),
		zap.String("format", string(format)),
		zap.String("version", string(version)),
	)

	// Reset reader before parsing
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var doc Document

	switch spec {
	case SBOMSpecSPDX:
		log.Debug("Initializing SPDX document parser",
			zap.String("format", string(format)),
			zap.String("version", string(version)),
		)
		doc, err = newSPDXDoc(ctx, r, format, version, sig)

	case SBOMSpecCDX:
		log.Debug("Initializing CycloneDX document parser",
			zap.String("format", string(format)),
		)
		doc, err = newCDXDoc(ctx, r, format, sig)

	default:
		log.Error("Unsupported SBOM specification",
			zap.String("spec", string(spec)),
		)
		return nil, errors.New("unsupported sbom format")
	}

	if err != nil {
		log.Error("Failed to parse SBOM document",
			zap.String("spec", string(spec)),
			zap.String("format", string(format)),
			zap.String("version", string(version)),
			zap.Error(err),
		)
		return nil, err
	}

	log.Debug("SBOM document parsed",
		zap.String("spec", string(spec)),
		zap.String("format", string(format)),
		zap.String("version", string(version)),
	)

	return doc, nil
}
