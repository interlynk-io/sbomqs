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
	"strings"
	"unicode"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
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
	SuppliedBy       GetSupplier
	OriginatedBy     GetManufacturer
	PrimaryComponent PrimaryComp
	Lifecycle        []string
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
		doc:             d,
		format:          format,
		config:          config,
		version:         version,
		spdxValidSchema: true,
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
	return s.Lifecycle
}

func (s Spdx3Doc) Manufacturer() GetManufacturer {
	return s.OriginatedBy
}

func (s Spdx3Doc) Supplier() GetSupplier {
	return s.SuppliedBy
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
	s.parseAuthors()
	s.parseTool()
}

func (s *Spdx3Doc) parseDoc() {
	log := logger.FromContext(s.config.Context)

	if s.doc == nil {
		log.Debug("spdx doc is not parsable")
		return
	}
}

func (s *Spdx3Doc) parseSpec() {
	sp := NewSpec()
	log := logger.FromContext(s.config.Context)
	log.Debug("parseSpec: starting spec parsing")

	sp.Format = string(s.format)
	sp.Version = string(s.version)
	sp.SpecType = string(SBOMSpecSPDX)

	log.Debugf("parseSpec: format=%s, version=%s, specType=%s", sp.Format, sp.Version, sp.SpecType)

	sp.Name = s.doc.SpdxDocument.Name
	sp.Spdxid = s.doc.SpdxDocument.SpdxID

	log.Debugf("parseSpec: document name=%s, spdxId=%s", sp.Name, sp.Spdxid)

	if s.doc.SpdxDocument.DataLicense != nil {
		log.Debugf("parseSpec: processing data license with spdxID=%s", s.doc.SpdxDocument.DataLicense.SpdxID)
		if lic := s.doc.GetAnyLicenseInfoByID(s.doc.SpdxDocument.DataLicense.SpdxID); lic != nil && lic.Name != "" {
			log.Debugf("parseSpec: found license info name=%s", lic.Name)
			lics := licenses.LookupExpression(lic.Name, nil)

			sp.Licenses = append(sp.Licenses, lics...)
			log.Debugf("parseSpec: added %d licenses from license info", len(lics))
		} else if s.doc.SpdxDocument.DataLicense.Name != "" {
			log.Debugf("parseSpec: using data license name=%s", s.doc.SpdxDocument.DataLicense.Name)
			lics := licenses.LookupExpression(s.doc.SpdxDocument.Name, nil)

			sp.Licenses = append(sp.Licenses, lics...)
			log.Debugf("parseSpec: added %d licenses from data license", len(lics))
		}
	} else {
		log.Debug("parseSpec: no data license found")
	}

	if s.doc.CreationInfo != nil {
		log.Debug("parseSpec: processing creation info")
		if !s.doc.CreationInfo.Created.IsZero() {
			sp.CreationTimestamp = s.doc.CreationInfo.Created.Format("2006-01-02T15:04:05Z")
			log.Debugf("parseSpec: creation timestamp=%s", sp.CreationTimestamp)
		} else {
			log.Debugf("parseSpec: creation timestamp not set")
		}
	} else {
		log.Debug("parseSpec: no creation info found")
	}

	// Document namespace is not a thing for SPDX3 as i believe
	// SPDXID in spdx3 are globally unique.
	sp.Namespace = ""
	sp.URI = s.doc.SpdxDocument.SpdxID

	if len(s.doc.CreationInfo.CreatedBy) > 0 {
		log.Debugf("parseSpec: processing %d created by agents", len(s.doc.CreationInfo.CreatedBy))

		for _, agentRef := range s.doc.CreationInfo.CreatedBy {
			agentType := s.doc.GetAgentTypeByID(agentRef.SpdxID)
			log.Debugf("parseSpec: checking agent spdxID=%s, type=%v", agentRef.SpdxID, agentType)

			if agentType != parse.AgentTypeOrganization {
				continue
			}

			agent := s.doc.GetAgentByID(agentRef.SpdxID)
			sp.Organization = agent.Name
			log.Debugf("parseSpec: found organization=%s", sp.Organization)
			break
		}
	} else {
		log.Debug("parseSpec: no created by agents found")
	}

	sp.isReqFieldsPresent = true

	log.Debugf("parseSpec: completed parsing spec for document=%s", sp.Name)
	s.SpdxSpec = sp
}
func (s *Spdx3Doc) parseAuthors() {
	log := logger.FromContext(s.config.Context)
	log.Debug("parseAuthors: starting author parsing")

	s.Auths = []GetAuthor{}

	if s.doc.CreationInfo == nil {
		log.Debugf("parseAuthors: no created by agents found")
		return
	}

	if len(s.doc.CreationInfo.CreatedBy) <= 0 {
		log.Debugf("parseAuthors: no created by agents found")
		return
	}

	log.Debugf("parseAuthors: processing %d created by agents", len(s.doc.CreationInfo.CreatedBy))

	for _, agentRef := range s.doc.CreationInfo.CreatedBy {
		agentType := s.doc.GetAgentTypeByID(agentRef.SpdxID)
		agent := s.doc.GetAgentByID(agentRef.SpdxID)
		log.Debugf("parseAuthors: checking agent spdxID=%s, type=%v, name=%s", agentRef.SpdxID, agentType, agent.Name)

		//TODO: SPDX3 does not have email????
		s.Auths = append(s.Auths, Author{
			Name:       agent.Name,
			Email:      "",
			AuthorType: string(agentType),
		})
	}

	log.Debug("parseAuthors: completed")
}

func (s *Spdx3Doc) parseTool() {
	log := logger.FromContext(s.config.Context)
	log.Debug("parseTools: starting author parsing")

	s.SpdxTools = []GetTool{}

	if s.doc.CreationInfo == nil {
		log.Debugf("parseTools: no created by agents found")
		return
	}

	if len(s.doc.CreationInfo.CreatedUsing) <= 0 {
		log.Debugf("parseTools: no created by agents found")
		return
	}

	// https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#68-creator-field
	// spdx2.3 spec says If the SPDX document was created using a software tool,
	// indicate the name and version for that tool
	extractVersion := func(inputName string) (string, string) {
		// Split the input string by "-"
		parts := strings.Split(inputName, "-")

		// if there are no "-" its a bad string
		if len(parts) == 1 {
			return inputName, ""
		}
		// The last element after splitting is the version
		version := parts[len(parts)-1]

		// The name is everything before the last element
		name := strings.Join(parts[:len(parts)-1], "-")

		// check if version has atleast one-digit
		// if not, then it is not a version
		for _, r := range version {
			if unicode.IsDigit(r) {
				return name, version
			}
		}

		// This is a bad case
		return inputName, ""
	}

	for _, tool := range s.doc.Tools {
		resolvedTool := s.doc.GetToolByID(tool.SpdxID)
		if resolvedTool == nil {
			continue
		}

		log.Debugf("parseTools: checking tool spdxID=%s, name=%s", resolvedTool.SpdxID, resolvedTool.Name)

		name, version := extractVersion(resolvedTool.Name)

		//TODO:SPDX3 does not have version for tools WTF
		s.SpdxTools = append(s.SpdxTools, Tool{
			Name:    name,
			Version: version,
		})
	}

	log.Debug("parseTools: completed")
}
