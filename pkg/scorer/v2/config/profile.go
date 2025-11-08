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

package config

import (
	"log"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
	"go.yaml.in/yaml/v2"
)

type Profile struct {
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Features    []ProfFeatures `yaml:"features"`
}

type ProfileConfig struct {
	Metadata struct {
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
		LastUpdated string `yaml:"last_updated"`
	} `yaml:"metadata"`

	Profiles []*Profile `yaml:"profiles"`
}

type ProfFeatures struct {
	Name        string `yaml:"name"`
	Disabled    bool   `yaml:"ignore"`
	Description string `yaml:"description"`
}

func DefaultProfConfig() string {
	config := ProfileConfig{}
	config.Metadata.Version = "2.0.0"
	config.Metadata.Description = "Configuration of Profile scoring."
	config.Metadata.LastUpdated = time.Now().Format("2006-01-02")

	// track categories using Map

	catal := registry.InitializeCatalog()
	allProfiles := catal.BaseProfiles()

	for _, p := range allProfiles {
		if p.Key == "" {
			continue
		}

		profile := &Profile{
			Name:        string(p.Name),
			Description: p.Description,
		}

		for _, feat := range p.Features {
			pFeat, ok := catal.ProfFeatures[feat]
			if !ok {
				continue
			}

			feature := &ProfFeatures{
				Name:        string(pFeat.Key),
				Description: pFeat.Description,
				Disabled:    pFeat.Required,
			}
			profile.Features = append(profile.Features, *feature)
		}
		config.Profiles = append(config.Profiles, profile)
	}

	d, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatal(err)
	}

	return string(d)
}
