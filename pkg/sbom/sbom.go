// Copyright 2023 Interlynk.io
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
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"gopkg.in/yaml.v2"
)

type SpecFormat string

const (
	SBOMSpecSPDX    SpecFormat = "spdx"
	SBOMSpecCDX     SpecFormat = "cyclonedx"
	SBOMSpecUnknown SpecFormat = "unknown"
)

type (
	FileFormat    string
	FormatVersion string
)

const (
	FileFormatJSON     FileFormat = "json"
	FileFormatRDF      FileFormat = "rdf"
	FileFormatYAML     FileFormat = "yaml"
	FileFormatTagValue FileFormat = "tag-value"
	FileFormatXML      FileFormat = "xml"
	FileFormatUnknown  FileFormat = "unknown"
)

type spdxbasic struct {
	ID      string `json:"SPDXID" yaml:"SPDXID"`
	Version string `json:"spdxVersion" yaml:"spdxVersion"`
}

type cdxbasic struct {
	XMLNS     string `json:"-" xml:"xmlns,attr"`
	BOMFormat string `json:"bomFormat" xml:"-"`
}

func SupportedSBOMSpecs() []string {
	return []string{string(SBOMSpecSPDX), string(SBOMSpecCDX)}
}

func SupportedSBOMSpecVersions(f string) []string {
	switch strings.ToLower(f) {
	case "cyclonedx":
		return cdxSpecVersions
	case "spdx":
		return spdxSpecVersions
	default:
		return []string{}
	}
}

func SupportedSBOMFileFormats(f string) []string {
	switch strings.ToLower(f) {
	case "cyclonedx":
		return cdxFileFormats
	case "spdx":
		return spdxFileFormats
	default:
		return []string{}
	}
}

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
			log.Printf("Failed to reset file pointer: %v", err)
		}
	}()

	formatGuess, err := guessFormat(f)
	if err != nil {
		return SBOMSpecUnknown, FileFormatUnknown, "", fmt.Errorf("failed to guess file format: %w", err)
	}

	switch formatGuess {
	case FileFormatJSON:
		log.Printf("format: %v", FileFormatJSON)

		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return SBOMSpecUnknown, FileFormatJSON, "", fmt.Errorf("failed to reset file pointer for SPDX JSON: %w", err)
		}

		var s spdxbasic
		if err := json.NewDecoder(f).Decode(&s); err == nil {
			if strings.HasPrefix(s.ID, "SPDX") {
				return SBOMSpecSPDX, FileFormatJSON, FormatVersion(s.Version), nil
			}
		} else {
			log.Printf("spdx-json sbom decoding failed: %v\n", err)
		}

		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return SBOMSpecUnknown, FileFormatJSON, "", fmt.Errorf("failed to reset file pointer for CycloneDX JSON: %w", err)
		}

		var cdx cdxbasic
		if err := json.NewDecoder(f).Decode(&cdx); err == nil {
			if cdx.BOMFormat == "CycloneDX" {
				return SBOMSpecCDX, FileFormatJSON, "", nil
			}
		} else {
			log.Printf("cyclonedx-json sbom decoding failed: %v\n", err)
		}

		return SBOMSpecUnknown, FileFormatJSON, "", fmt.Errorf("failed to decode the SPDX or CycloneDX SBOM JSON content")

	case FileFormatYAML:
		log.Printf("format: %v", FileFormatYAML)

		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			return SBOMSpecUnknown, FileFormatYAML, "", fmt.Errorf("failed to reset file pointer for SPDX YAML: %w", err)
		}

		var y spdxbasic
		if err := yaml.NewDecoder(f).Decode(&y); err == nil {
			if strings.HasPrefix(y.ID, "SPDX") {
				return SBOMSpecSPDX, FileFormatYAML, FormatVersion(y.Version), nil
			}
		} else {
			return SBOMSpecUnknown, FileFormatYAML, "", fmt.Errorf("failed to decode YAML content")
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return SBOMSpecUnknown, FileFormatUnknown, "", fmt.Errorf("failed to reset file pointer: %w", err)
	}

	var cdx cdxbasic
	if err := xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, "", nil
		}
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return SBOMSpecUnknown, FileFormatUnknown, "", fmt.Errorf("failed to reset file pointer: %w", err)
	}

	if sc := bufio.NewScanner(f); sc.Scan() {
		if strings.HasPrefix(sc.Text(), "SPDX") {
			return SBOMSpecSPDX, FileFormatTagValue, "", nil
		}
	}

	return SBOMSpecUnknown, FileFormatUnknown, "", nil
}

func guessFormat(f io.ReadSeeker) (FileFormat, error) {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
			return FileFormatJSON, nil
		}
		if strings.Contains(line, ":") || strings.HasPrefix(line, "-") {
			return FileFormatYAML, nil
		}
		break
	}

	if err := scanner.Err(); err != nil {
		return FileFormatUnknown, fmt.Errorf("error scanning file: %w", err)
	}

	return FileFormatUnknown, nil
}

func NewSBOMDocument(ctx context.Context, f io.ReadSeeker, sig Signature) (Document, error) {
	log := logger.FromContext(ctx)

	spec, format, version, err := detectSbomFormat(f)
	log.Debugf("SBOM detect spec:%s format:%s", spec, format)
	if err != nil {
		return nil, err
	}

	// log.Debugf("SBOM detect spec:%s format:%s", spec, format)

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
