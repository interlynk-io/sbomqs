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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"gopkg.in/yaml.v2"
)

type SBOMSpecFormat string

const (
	SBOMSpecSPDX    SBOMSpecFormat = "spdx"
	SBOMSpecCDX     SBOMSpecFormat = "cyclonedx"
	SBOMSpecUnknown SBOMSpecFormat = "unknown"
)

type FileFormat string

const (
	FileFormatJSON     FileFormat = "json"
	FileFormatRDF      FileFormat = "rdf"
	FileFormatYAML     FileFormat = "yaml"
	FileFormatTagValue FileFormat = "tag-value"
	FileFormatXML      FileFormat = "xml"
	FileFormatUnknown  FileFormat = "unknown"
)

type spdxbasic struct {
	ID string `json:"SPDXID" yaml:"SPDXID"`
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
		return cdx_spec_versions
	case "spdx":
		return spdx_spec_versions
	default:
		return []string{}
	}
}

func SupportedSBOMFileFormats(f string) []string {
	switch strings.ToLower(f) {
	case "cyclonedx":
		return cdx_file_formats
	case "spdx":
		return spdx_file_formats
	default:
		return []string{}
	}
}

func SupportedPrimaryPurpose(f string) []string {
	switch strings.ToLower(f) {
	case "cyclonedx":
		return cdx_primary_purpose
	case "spdx":
		return spdx_primary_purpose
	default:
		return []string{}
	}
}

func detectSbomFormat(f io.ReadSeeker) (SBOMSpecFormat, FileFormat, error) {
	defer f.Seek(0, io.SeekStart)

	f.Seek(0, io.SeekStart)

	var s spdxbasic
	if err := json.NewDecoder(f).Decode(&s); err == nil {
		if strings.HasPrefix(s.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatJSON, nil
		}
	}

	f.Seek(0, io.SeekStart)

	var cdx cdxbasic
	if err := json.NewDecoder(f).Decode(&cdx); err == nil {
		if cdx.BOMFormat == "CycloneDX" {
			return SBOMSpecCDX, FileFormatJSON, nil
		}
	}

	f.Seek(0, io.SeekStart)

	if err := xml.NewDecoder(f).Decode(&cdx); err == nil {
		if strings.HasPrefix(cdx.XMLNS, "http://cyclonedx.org") {
			return SBOMSpecCDX, FileFormatXML, nil
		}
	}
	f.Seek(0, io.SeekStart)

	if sc := bufio.NewScanner(f); sc.Scan() {
		if strings.HasPrefix(sc.Text(), "SPDX") {
			return SBOMSpecSPDX, FileFormatTagValue, nil
		}
	}

	f.Seek(0, io.SeekStart)

	var y spdxbasic
	if err := yaml.NewDecoder(f).Decode(&y); err == nil {
		if strings.HasPrefix(y.ID, "SPDX") {
			return SBOMSpecSPDX, FileFormatYAML, nil
		}
	}

	return SBOMSpecUnknown, FileFormatUnknown, nil
}

func NewSBOMDocument(ctx context.Context, f io.ReadSeeker) (Document, error) {
	log := logger.FromContext(ctx)

	spec, format, err := detectSbomFormat(f)
	if err != nil {
		return nil, err
	}

	log.Debugf("SBOM detect spec:%s format:%s", spec, format)

	var doc Document

	switch spec {
	case SBOMSpecSPDX:
		doc, err = newSPDXDoc(ctx, f, format)
	case SBOMSpecCDX:
		doc, err = newCDXDoc(ctx, f, format)
	default:
		return nil, errors.New("unsupported sbom spec")
	}

	return doc, err
}
