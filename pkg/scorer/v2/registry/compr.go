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

package registry

import (
	"log"
	"os"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"go.yaml.in/yaml/v2"
)

type ComprConfig struct {
	Metadata struct {
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
		LastUpdated string `yaml:"last_updated"`
	} `yaml:"metadata"`

	Categories []CatSpec `yaml:"categories"`
}

type CatSpec struct {
	Name        string
	Description string
	Key         string
	Weight      float64
	Features    []FeatSpec
}
type FeatSpec struct {
	Name   string
	Ignore bool
	Key    string
	Weight float64
}

func DefaultComprConfig() string {
	config := ComprConfig{}
	config.Metadata.Version = "2.0.0"
	config.Metadata.Description = "Configuration of SBOM scoring features, grouped by category"
	config.Metadata.LastUpdated = time.Now().Format("2006-01-02")

	for _, cat := range comprehenssiveCategories {
		category := CatSpec{
			Name:        cat.Name,
			Key:         cat.Key,
			Weight:      cat.Weight,
			Description: cat.Description,
		}

		for _, pFeat := range cat.Features {

			feature := FeatSpec{
				Name:   pFeat.Name,
				Key:    pFeat.Key,
				Weight: pFeat.Weight,
				Ignore: pFeat.Ignore,
			}
			category.Features = append(category.Features, feature)
		}
		config.Categories = append(config.Categories, category)
	}

	d, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatal(err)
	}

	return string(d)
}

// ReadComprConfigFile decodes a YAML file into the ComprConfig struct.
func ReadComprConfigFile(path string) ([]catalog.ComprCatSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ComprConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	var cat []catalog.ComprCatSpec

	for _, c := range cfg.Categories {

		category := catalog.ComprCatSpec{
			Name:        c.Name,
			Key:         c.Key,
			Description: c.Description,
			Weight:      c.Weight,
		}
		for _, f := range c.Features {
			if f.Ignore {
				continue
			}

			feat := catalog.ComprFeatSpec{
				Name:     f.Name,
				Ignore:   f.Ignore,
				Key:      f.Key,
				Weight:   f.Weight,
				Evaluate: CompKeyToEvaluatingFunction[f.Key],
			}

			category.Features = append(category.Features, feat)
		}
		cat = append(cat, category)

	}

	// cat  := cfg.Categories
	return cat, nil
}
