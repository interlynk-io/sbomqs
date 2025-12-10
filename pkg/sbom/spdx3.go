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
	"context"
	"fmt"
	"io"
	"os"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom/internal/parser"
	"github.com/interlynk-io/spdx-zen/parse"
)

// spdx3Doc is a wrapper around the spdx-zen document.
type Spdx3Doc struct {
	doc              *parse.Document
	format           FileFormat
	version          FormatVersion
	config           *parser.Config
	SpdxSpec         *Specs
	Comps            []GetComponent
	Auths            []GetAuthor
	SpdxTools        []GetTool
	Rels             []GetRelation
	PrimaryComponent PrimaryComp
	Lifecycle        string
	Dependencies     map[string][]string
	composition      map[string]string
	Vuln             []GetVulnerabilities
	spdxValidSchema  bool
}

// newSPDX3Doc creates a new SPDX 3.x document using the spdx-zen parser
func newSPDX3Doc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion) (Document, error) {
	opts := []SPDXOption{parser.WithContext(ctx)}
	return newSPDX3DocWithOptions(f, format, version, opts...)
}

func newSPDX3DocWithOptions(f io.ReadSeeker, format FileFormat, version FormatVersion, opts ...SPDXOption) (Document, error) {
	config := parser.DefaultConfig()

	for _, opt := range opts {
		opt.Apply(config)
	}

	_ = logger.FromContext(config.Context)

	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	var d *parse.Document
	reader := parse.NewReader()

	d, err = reader.FromReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading SPDX document from file: %v\n", err)
		os.Exit(1)
	}

	doc := &Spdx3Doc{
		doc:     d,
		format:  format,
		config:  config,
		version: version,
	}

	doc.parse()

	return doc, nil
}

func (s Spdx3Doc) PrimaryComp() GetPrimaryComp {
	return &s.PrimaryComponent
}

func (s Spdx3Doc) Spec() Spec {
	return *s.SpdxSpec
}

func (s Spdx3Doc) Components() []GetComponent {
	return s.Comps
}

func (s Spdx3Doc) Authors() []GetAuthor {
	return s.Auths
}

func (s Spdx3Doc) Tools() []GetTool {
	return s.SpdxTools
}

func (s Spdx3Doc) Relations() []GetRelation {
	return s.Rels
}

func (s Spdx3Doc) Logs() []string {
	return nil
}

func (s Spdx3Doc) Lifecycles() []string {
	return []string{s.Lifecycle}
}

func (s Spdx3Doc) Manufacturer() GetManufacturer {
	return nil
}

func (s Spdx3Doc) Supplier() GetSupplier {
	return nil
}

func (s Spdx3Doc) GetRelationships(componentID string) []string {
	return s.Dependencies[componentID]
}

func (s Spdx3Doc) GetComposition(componentID string) string {
	return s.composition[componentID]
}

func (s Spdx3Doc) Vulnerabilities() []GetVulnerabilities {
	return s.Vuln
}

func (s Spdx3Doc) Signature() GetSignature {
	// SPDX does not support signatures in its specification
	return nil
}

func (s Spdx3Doc) SchemaValidation() bool {
	return s.spdxValidSchema
}

func (s *Spdx3Doc) parse() {
	s.parseDoc()
	s.parseSpec()
}

func (s *Spdx3Doc) parseDoc() {
}

func (s *Spdx3Doc) parseSpec() {
}
