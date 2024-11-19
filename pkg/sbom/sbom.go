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
	var err error
	defer func() {
		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			log.Printf("Failed to seek: %v", err)
		}
	}()

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Fatalf("Failed to seek: %v", err)
	}

	var s spdxbasic
	if err = json.NewDecoder(f).Decode(&s); err == nil {
		if strings.HasPrefix(s.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatJSON, FormatVersion(s.Version), nil
		}
	} else {
		return SBOMSpecSPDX, FileFormatJSON, FormatVersion(s.Version), err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	var cdx cdxbasic
	if err = json.NewDecoder(f).Decode(&cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			return SBOMSpecCDX, FileFormatJSON, "", nil
		}
	} else {
		return SBOMSpecCDX, FileFormatJSON, "", err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		log.Printf("Failed to seek: %v", err)
	}

	if err = xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, "", nil
		}
	} else {
		return SBOMSpecCDX, FileFormatJSON, "", err
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
	if err = yaml.NewDecoder(f).Decode(&y); err == nil {
		if strings.HasPrefix(y.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatYAML, FormatVersion(s.Version), nil
		}
	} else {
		return SBOMSpecSPDX, FileFormatYAML, FormatVersion(s.Version), nil
	}

	return SBOMSpecUnknown, FileFormatUnknown, "", err
}

func NewSBOMDocument(ctx context.Context, f io.ReadSeeker) (Document, error) {
	log := logger.FromContext(ctx)

	spec, format, version, err := detectSbomFormat(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("SBOM detect spec:%s format:%s", spec, format)

	var doc Document

	switch spec {
	case SBOMSpecSPDX:
		doc, err = newSPDXDoc(ctx, f, format, version)
	case SBOMSpecCDX:
		doc, err = newCDXDoc(ctx, f, format)
	default:
		return nil, errors.New("unsupported sbom format")
	}

	return doc, err
}
