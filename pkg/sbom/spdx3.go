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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/spdx-zen/parse"
)

// Spdx3Doc represents an SPDX 3.x document with its parsed components
type Spdx3Doc struct {
	doc     *parse.Document
	format  FileFormat
	version FormatVersion
	ctx     context.Context

	SpdxSpec         *Specs
	PrimaryComponent PrimaryComp
}

// newSPDX3Doc creates a new SPDX 3.x document using the spdx-zen parser
func newSPDX3Doc(ctx context.Context, f io.ReadSeeker, format FileFormat, version FormatVersion) (Document, error) {
	// Reset to beginning of file
	_, err := f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	// Read the entire content
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read SPDX 3.x document: %w", err)
	}

	// Parse using spdx-zen
	reader := parse.NewReader()
	doc, err := reader.Read(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPDX 3.x document: %w", err)
	}

	s := &Spdx3Doc{
		doc:     doc,
		format:  format,
		version: version,
		ctx:     ctx,
	}

	s.parseSpec()

	return s, nil
}

// parseSpec extracts document metadata and populates the Specs struct
func (s *Spdx3Doc) parseSpec() {
	log := logger.FromContext(s.ctx)
	log.Debug("spdx3 parseSpec()")

	sp := NewSpec()

	// Format and type
	sp.Format = string(s.format)
	sp.SpecType = string(SBOMSpecSPDX)

	// From CreationInfo
	if s.doc.CreationInfo != nil {
		// Prefix version with "SPDX-" to match SPDX 2.x convention
		sp.Version = "SPDX-" + s.doc.CreationInfo.SpecVersion
		sp.CreationTimestamp = s.doc.CreationInfo.Created.Format("2006-01-02T15:04:05Z")
		sp.Comment = s.doc.CreationInfo.Comment

		log.Debugf("spdx3 doc specVersion: %s", sp.Version)
		log.Debugf("spdx3 doc creationTimestamp: %s", sp.CreationTimestamp)

		// Extract organization from createdBy agents
		// First try agents from CreationInfo
		for _, agent := range s.doc.CreationInfo.CreatedBy {
			name := agent.Name
			log.Debugf("spdx3 doc createdBy agent: %s (spdxId: %s)", name, agent.SpdxID)
			// Check if the name indicates an organization (e.g., "Organization: Interlynk")
			if strings.HasPrefix(name, "Organization:") {
				sp.Organization = strings.TrimSpace(strings.TrimPrefix(name, "Organization:"))
				log.Debugf("spdx3 doc organization: %s", sp.Organization)
				break
			}
		}

		// If no organization found from CreationInfo, try parsed Agents
		if sp.Organization == "" && len(s.doc.Agents) > 0 {
			for _, agent := range s.doc.Agents {
				name := agent.Name
				log.Debugf("spdx3 doc agent from graph: %s (spdxId: %s)", name, agent.SpdxID)
				if strings.HasPrefix(name, "Organization:") {
					sp.Organization = strings.TrimSpace(strings.TrimPrefix(name, "Organization:"))
					log.Debugf("spdx3 doc organization: %s", sp.Organization)
					break
				}
			}
		}
	} else {
		log.Debug("spdx3 doc is missing CreationInfo")
	}

	// From SpdxDocument
	if s.doc.SpdxDocument != nil {
		sp.Name = s.doc.SpdxDocument.Name
		sp.Spdxid = s.doc.SpdxDocument.SpdxID

		log.Debugf("spdx3 doc name: %s", sp.Name)
		log.Debugf("spdx3 doc spdxId: %s", sp.Spdxid)

		// Extract namespace from namespaceMap
		if len(s.doc.SpdxDocument.NamespaceMap) > 0 {
			sp.Namespace = s.doc.SpdxDocument.NamespaceMap[0].Namespace
			sp.URI = sp.Namespace
			log.Debugf("spdx3 doc namespace: %s", sp.Namespace)
		} else {
			log.Debug("spdx3 doc has no namespaceMap")
		}

		// Extract comment from SpdxDocument if not already set from CreationInfo
		if sp.Comment == "" && s.doc.SpdxDocument.Comment != "" {
			sp.Comment = s.doc.SpdxDocument.Comment
		}

		// Extract dataLicense
		if s.doc.SpdxDocument.DataLicense != nil {
			licName := s.doc.SpdxDocument.DataLicense.Name
			if licName != "" {
				lics := licenses.LookupExpression(licName, nil)
				sp.Licenses = append(sp.Licenses, lics...)
				log.Debugf("spdx3 doc dataLicense: %s", licName)
			}
		} else {
			log.Debug("spdx3 doc has no dataLicense")
		}
	} else {
		log.Debug("spdx3 doc is missing SpdxDocument element")
	}

	// Extract external document references from ExternalMaps
	for _, extMap := range s.doc.ExternalMaps {
		if extMap.ExternalSpdxId != "" {
			sp.ExternalDocReference = append(sp.ExternalDocReference, extMap.ExternalSpdxId)
			log.Debugf("spdx3 doc externalDocRef: %s", extMap.ExternalSpdxId)
		}
	}

	sp.isReqFieldsPresent = s.requiredFields()
	log.Debugf("spdx3 doc requiredFields present: %t", sp.isReqFieldsPresent)

	s.SpdxSpec = sp
}

// requiredFields checks if all required SPDX 3.x fields are present
func (s *Spdx3Doc) requiredFields() bool {
	log := logger.FromContext(s.ctx)

	if s.doc == nil {
		log.Debug("spdx3 doc is nil")
		return false
	}

	hasRequiredFields := true

	// CreationInfo is required
	if s.doc.CreationInfo == nil {
		log.Debug("spdx3 doc is missing required CreationInfo")
		hasRequiredFields = false
	} else {
		// specVersion is required
		if s.doc.CreationInfo.SpecVersion == "" {
			log.Debug("spdx3 doc is missing required specVersion")
			hasRequiredFields = false
		}

		// created timestamp is required
		if s.doc.CreationInfo.Created.IsZero() {
			log.Debug("spdx3 doc is missing required created timestamp")
			hasRequiredFields = false
		}

		// createdBy is required (at least one creator)
		if len(s.doc.CreationInfo.CreatedBy) == 0 {
			log.Debug("spdx3 doc is missing required createdBy")
			hasRequiredFields = false
		}
	}

	// SpdxDocument is required
	if s.doc.SpdxDocument == nil {
		log.Debug("spdx3 doc is missing required SpdxDocument element")
		hasRequiredFields = false
	} else {
		// SpdxDocument must have spdxId
		if s.doc.SpdxDocument.SpdxID == "" {
			log.Debug("spdx3 doc SpdxDocument is missing required spdxId")
			hasRequiredFields = false
		}
	}

	return hasRequiredFields
}

// Spec returns the SBOM specification information
func (s Spdx3Doc) Spec() Spec {
	return *s.SpdxSpec
}

// SchemaValidation returns whether the SBOM passes schema validation
func (s Spdx3Doc) SchemaValidation() bool {
	// For now, if we successfully parsed the document, consider it valid
	return s.doc != nil
}

// Components returns all components defined in the SBOM
func (s Spdx3Doc) Components() []GetComponent {
	// TODO: Implement component parsing in future
	return nil
}

// Relations returns all relationships defined in the SBOM
func (s Spdx3Doc) Relations() []GetRelation {
	// TODO: Implement relationship parsing in future
	return nil
}

// Authors returns the authors of the SBOM
func (s Spdx3Doc) Authors() []GetAuthor {
	// TODO: Implement author parsing in future
	return nil
}

// Tools returns the tools used to create the SBOM
func (s Spdx3Doc) Tools() []GetTool {
	// TODO: Implement tool parsing in future
	return nil
}

// Logs returns any log messages associated with the SBOM processing
func (s Spdx3Doc) Logs() []string {
	return nil
}

// Lifecycles returns the lifecycle phases represented in the SBOM
func (s Spdx3Doc) Lifecycles() []string {
	return nil
}

// Manufacturer returns the manufacturer information for the SBOM
func (s Spdx3Doc) Manufacturer() GetManufacturer {
	return nil
}

// Supplier returns the supplier information for the SBOM
func (s Spdx3Doc) Supplier() GetSupplier {
	return nil
}

// PrimaryComp returns information about the primary component in the SBOM
func (s Spdx3Doc) PrimaryComp() GetPrimaryComp {
	// TODO: Implement primary component detection in future
	return &s.PrimaryComponent
}

// GetRelationships returns relationships for the specified component ID
func (s Spdx3Doc) GetRelationships(componentID string) []string {
	// TODO: Implement relationship lookup in future
	return nil
}

// Vulnerabilities returns all vulnerabilities defined in the SBOM
func (s Spdx3Doc) Vulnerabilities() []GetVulnerabilities {
	return nil
}

// Signature returns the cryptographic signature information for the SBOM
func (s Spdx3Doc) Signature() GetSignature {
	return nil
}
