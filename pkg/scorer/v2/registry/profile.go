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

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"go.yaml.in/yaml/v2"
)

type ProfileConfig struct {
	Metadata struct {
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
		LastUpdated string `yaml:"last_updated"`
	} `yaml:"metadata"`

	Profiles []Prof `yaml:"profiles"`
}

type Prof struct {
	Name        string
	Description string
	Key         string
	Features    []ProfFSpec
}

type ProfFSpec struct {
	Name        string
	Required    bool
	Description string
	Key         string
}

func DefaultProfConfig() string {
	config := ProfileConfig{}
	config.Metadata.Version = "2.0.0"
	config.Metadata.Description = "Configuration of Profile scoring."
	config.Metadata.LastUpdated = time.Now().Format("2006-01-02")

	// track categories using Map

	for _, p := range Profile {
		if p.Key == "" {
			continue
		}

		profile := &Prof{
			Key:         string(p.Key),
			Name:        p.Name,
			Description: p.Description,
		}

		for _, pFeat := range p.Features {
			feature := ProfFSpec{
				Name:        pFeat.Name,
				Key:         pFeat.Key,
				Description: pFeat.Description,
				Required:    pFeat.Required,
			}

			profile.Features = append(profile.Features, feature)
		}
		config.Profiles = append(config.Profiles, *profile)
	}

	d, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatal(err)
	}

	return string(d)
}

// ReadProfileConfigFile decodes a YAML file into the ProfileConfig struct.
func ReadProfileConfigFile(path string) ([]catalog.ProfSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ProfileConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	var pro []catalog.ProfSpec

	for _, p := range cfg.Profiles {
		profile := catalog.ProfSpec{
			Name:        p.Name,
			Description: p.Description,
			Key:         catalog.ProfileKey(p.Key),
		}

		switch p.Key {
		case string(ProfileNTIA):
			profile.Features = similar(p, NTIAKeyToEvaluatingFunction)

		case string(ProfileNTIA2025):
			profile.Features = similar(p, NTIA2025KeyToEvaluatingFunction)

		case string(ProfileBSI11):
			profile.Features = similar(p, BSIV11KeyToEvaluatingFunction)

		case string(ProfileBSI20):
			profile.Features = similar(p, BSIV20KeyToEvaluatingFunction)

		case string(ProfileOCT):
			profile.Features = similar(p, OCTKeyToEvaluatingFunction)

		case string(ProfileInterlynk):
			profile.Features = similar(p, InterlynkKeyToEvaluatingFunction)

		default:
			// kkk
		}

		pro = append(pro, profile)
	}
	return pro, nil
}

func similar(p Prof, eval map[string]catalog.ProfFeatEval) []catalog.ProfFeatSpec {
	var profSpec []catalog.ProfFeatSpec

	for _, f := range p.Features {

		feat := catalog.ProfFeatSpec{
			Name:        f.Name,
			Description: f.Description,
			Key:         f.Key,
			Required:    f.Required,
			Evaluate:    eval[f.Key],
		}
		profSpec = append(profSpec, feat)

	}
	return profSpec
}
