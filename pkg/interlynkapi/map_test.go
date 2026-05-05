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

package interlynkapi

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPayloads tests
func TestBuildPayloads(t *testing.T) {
	tests := []struct {
		name         string
		comps        []sbom.GetComponent
		wantCount    int
		wantNames    []string
		wantVersions []string
	}{
		{
			name:      "empty_components",
			comps:     []sbom.GetComponent{},
			wantCount: 0,
		},
		{
			name:      "nil_components",
			comps:     nil,
			wantCount: 0,
		},
		{
			name:         "single_component",
			comps:        []sbom.GetComponent{makeComponent("test-pkg", "1.0.0", nil, nil, "")},
			wantCount:    1,
			wantNames:    []string{"test-pkg"},
			wantVersions: []string{"1.0.0"},
		},
		{
			name: "multiple_components",
			comps: []sbom.GetComponent{
				makeComponent("pkg-a", "1.0.0", nil, nil, ""),
				makeComponent("pkg-b", "2.0.0", nil, nil, ""),
				makeComponent("pkg-c", "3.0.0", nil, nil, ""),
			},
			wantCount:    3,
			wantNames:    []string{"pkg-a", "pkg-b", "pkg-c"},
			wantVersions: []string{"1.0.0", "2.0.0", "3.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := buildPayloads(context.Background(), tt.comps)
			assert.Len(t, payloads, tt.wantCount)
			for i, name := range tt.wantNames {
				assert.Equal(t, name, payloads[i].Name)
			}
			for i, version := range tt.wantVersions {
				assert.Equal(t, version, payloads[i].Version)
			}
		})
	}
}

// Real-world scenarios
func TestMapComponent_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name         string
		comp         sbom.GetComponent
		wantName     string
		wantVersion  string
		wantPurl     string
		wantPurlNil  bool
		wantCpeCount int
		wantLicense  string
	}{
		{
			name: "maven_component",
			comp: makeComponent("log4j-core", "2.17.0",
				[]purl.PURL{purl.NewPURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0")},
				[]cpe.CPE{cpe.NewCPE("cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*")},
				"Apache-2.0"),
			wantName:     "log4j-core",
			wantVersion:  "2.17.0",
			wantPurl:     "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
			wantCpeCount: 1,
			wantLicense:  "Apache-2.0",
		},
		{
			name: "npm_component",
			comp: makeComponent("lodash", "4.17.21",
				[]purl.PURL{purl.NewPURL("pkg:npm/lodash@4.17.21")},
				nil,
				"MIT"),
			wantName:     "lodash",
			wantVersion:  "4.17.21",
			wantPurl:     "pkg:npm/lodash@4.17.21",
			wantCpeCount: 0,
			wantLicense:  "MIT",
		},
		{
			name: "minimal_component",
			comp: func() sbom.GetComponent {
				c := sbom.NewComponent()
				c.Name = "minimal"
				c.Version = ""
				return c
			}(),
			wantName:     "minimal",
			wantVersion:  "",
			wantPurlNil:  true,
			wantCpeCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mapComponent(tt.comp)

			assert.Equal(t, tt.wantName, payload.Name)
			assert.Equal(t, tt.wantVersion, payload.Version)
			assert.Len(t, payload.Cpes, tt.wantCpeCount)

			if tt.wantPurlNil {
				assert.Nil(t, payload.Purl)
			} else {
				require.NotNil(t, payload.Purl)
				assert.Equal(t, tt.wantPurl, *payload.Purl)
			}

			if tt.wantLicense != "" {
				require.NotNil(t, payload.License)
				assert.Equal(t, tt.wantLicense, *payload.License)
			}
		})
	}
}

// Edge cases

func TestMapComponent_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		comp        sbom.GetComponent
		wantName    string
		wantVersion string
	}{
		{
			name: "whitespace_trimming",
			comp: func() sbom.GetComponent {
				c := sbom.NewComponent()
				c.Name = "  spaced-name  "
				c.Version = "  1.0.0  "
				return c
			}(),
			wantName:    "spaced-name",
			wantVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mapComponent(tt.comp)

			assert.Equal(t, tt.wantName, payload.Name)
			assert.Equal(t, tt.wantVersion, payload.Version)
		})
	}
}

// Complete component test
func TestMapComponent_Complete(t *testing.T) {
	comp := makeComponent("complete-pkg", "1.2.3",
		[]purl.PURL{purl.NewPURL("pkg:generic/complete-pkg@1.2.3")},
		[]cpe.CPE{
			cpe.NewCPE("cpe:2.3:a:vendor:complete-pkg:1.2.3:*:*:*:*:*:*:*"),
		},
		"BSD-3-Clause")

	payload := mapComponent(comp)

	assert.Equal(t, "complete-pkg", payload.Name)
	assert.Equal(t, "1.2.3", payload.Version)
	require.NotNil(t, payload.Purl)
	assert.Equal(t, "pkg:generic/complete-pkg@1.2.3", *payload.Purl)
	assert.Len(t, payload.Cpes, 1)
	require.NotNil(t, payload.License)
	assert.Equal(t, "BSD-3-Clause", *payload.License)
}

// makeComponent is a test helper to create components with optional fields
func makeComponent(name, version string, purls []purl.PURL, cpes []cpe.CPE, license string) sbom.GetComponent {
	c := sbom.NewComponent()
	c.Name = name
	c.Version = version
	c.Purls = purls
	c.Cpes = cpes
	if license != "" {
		c.Licenses = []licenses.License{licenses.CreateCustomLicense(license, license)}
	}
	return c
}
