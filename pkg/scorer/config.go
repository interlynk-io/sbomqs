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

package scorer

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Metadata struct {
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
		LastUpdated string `yaml:"last_updated"`
	} `yaml:"metadata"`

	Categories []*Cat `yaml:"categories"`
}

type Cat struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Features    []Features `yaml:"features"`
}
type Features struct {
	Name        string `yaml:"name"`
	Disabled    bool   `yaml:"ignore"`
	Description string `yaml:"description"`
}

// Category descriptions
var categoryDescriptions = map[string]string{
	"Structural":            "Features related to the SBOM's spec and format",
	"NTIA-minimum-elements": "Features ensuring compliance with NTIA minimum elements (2021) for SBOMs",
	"bsi-v1.1":              "Features ensuring compliance with BSI v1.1 SBOM requirements",
	"bsi-v2.0":              "Features ensuring compliance with BSI v2.0 SBOM requirements",
	"Semantic":              "Features related to the meaning and completeness of SBOM data",
	"Quality":               "Features assessing the quality of SBOM data",
	"Sharing":               "Features related to SBOM sharing and distribution",
}

// feature key mapped to descriptions
var featureDescriptions = map[string]string{
	"sbom_spec":                      "SBOM specification",
	"sbom_spec_version":              "SBOM specification version",
	"sbom_file_format":               "SBOM file format",
	"sbom_parsable":                  "SBOM is machine-parsable",
	"comp_with_supplier":             "components have supplier",
	"comp_with_name":                 "components have a name",
	"comp_with_version":              "components have a version",
	"comp_with_uniq_ids":             "components have unique identifiers",
	"sbom_dependencies":              "Primary Comp with dependencies",
	"sbom_authors":                   "SBOM has authors",
	"sbom_creation_timestamp":        "SBOM has a creation timestamp",
	"comp_with_licenses":             "components have license information",
	"comp_with_checksums":            "components have checksums for verification",
	"comp_with_checksums_sha256":     "components have SHA256 checksums",
	"comp_with_source_code_uri":      "components have a source code URI",
	"comp_with_source_code_hash":     "components have a source code hash",
	"comp_with_executable_uri":       "components have an executable URI",
	"comp_with_executable_hash":      "components have executable checksums",
	"spec_with_version_compliant":    "SBOM specification version is compliant",
	"sbom_with_uri":                  "SBOM has a URI",
	"sbom_required_fields":           "SBOM has all required fields per specification",
	"comp_valid_licenses":            "components have valid licenses",
	"comp_with_primary_purpose":      "components have a primary purpose",
	"comp_with_deprecated_licenses":  "components have deprecated licenses",
	"comp_with_restrictive_licenses": "components have restrictive licenses",
	"comp_with_any_vuln_lookup_id":   "components have at least one vulnerability lookup ID",
	"comp_with_multi_vuln_lookup_id": "components have multiple vulnerability lookup IDs",
	"sbom_with_creator_and_version":  "SBOM has a creator and version",
	"sbom_with_primary_component":    "SBOM has a primary component",
	"sbom_sharable":                  "SBOM has a license permitting sharing",
	"comp_with_associated_license":   "components have associated licenses",
	"comp_with_concluded_license":    "components have concluded licenses",
	"comp_with_declared_license":     "components have declared licenses",
	"comp_with_dependencies":         "components have dependencies",
	"sbom_with_vuln":                 "SBOM has vulnerability information",
	"sbom_build_process":             "SBOM has build process information",
	"sbom_with_signature":            "SBOM has a digital signature",
}

func DefaultConfig() string {
	config := Config{}
	config.Metadata.Version = "1.0.0"
	config.Metadata.Description = "Configuration of SBOM scoring features, grouped by category"
	config.Metadata.LastUpdated = time.Now().Format("2006-01-02")

	// track categories using Map
	categoryMap := make(map[string]*Cat)

	for _, c := range checks {
		if c.Category == "" || c.Key == "" {
			continue
		}

		catKey := c.Category

		// get or create category
		cat, exists := categoryMap[catKey]
		if !exists {
			cat = &Cat{
				Name:        catKey,
				Description: categoryDescriptions[catKey],
			}
			if cat.Description == "" {
				cat.Description = "Features for " + catKey
			}
			categoryMap[catKey] = cat
			config.Categories = append(config.Categories, cat)
		}

		feature := Features{
			Name:        c.Key,
			Disabled:    c.Ignore,
			Description: featureDescriptions[c.Key],
		}
		if feature.Description == "" {
			feature.Description = c.Descr
		}
		cat.Features = append(cat.Features, feature)
	}

	d, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatal(err)
	}

	return string(d)
}

func ReadConfigFile(path string) ([]Filter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	err = yaml.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	filters := []Filter{}
	for _, cat := range cfg.Categories {
		if cat == nil || len(cat.Features) == 0 {
			continue
		}

		for _, f := range cat.Features {
			if f.Disabled {
				continue
			}

			filter := Filter{
				Name:     f.Name,
				Ftype:    Mix,
				Category: cat.Name,
			}
			filters = append(filters, filter)
		}
	}
	return filters, nil
}
