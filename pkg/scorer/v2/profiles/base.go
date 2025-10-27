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

package profiles

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/stretchr/testify/assert/yaml"
)

// YAML schema + loader (from file or built-ins).

// ReadProfileFile reads, unmarshal, validates and returns a config.
func ReadProfileFile(path string) (*Config, error) {
	cfgData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		return nil, fmt.Errorf("profiles: yaml decode: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("profiles: nil")
	}

	if len(cfg.Profiles) == 0 {
		return errors.New("profiles: no profiles found")
	}

	profileExist := make(map[string]bool)

	for i, profile := range cfg.Profiles {

		// validate profile name, duplicacy, etc
		if err := validateProfile(i, profile, profileExist); err != nil {
			return err
		}

		// validate profile features
		if err := validateProfileFeatures(profile); err != nil {
			return err
		}
	}

	return nil
}

func validateProfileFeatures(profile api.ProfileResult) error {
	// validate profile features
	featureExists := make(map[string]bool)
	for i, feat := range profile.ProfileResult {
		key := strings.TrimSpace(feat.Name)

		if key == "" {
			return fmt.Errorf("profiles: profile %q has empty feature.name at index %d", profile.Name, i)
		}

		if _, dup := featureExists[key]; dup {
			return fmt.Errorf("profiles: profile %q has duplicate feature %q", profile.Name, key)
		}

		featureExists[key] = true

		// now validate this key with that profile having list of keys already with it.
	}
	return nil
}

func validateProfile(i int, profile Profile, profileExist map[string]bool) error {
	pfName := strings.TrimSpace(profile.Name)
	if pfName == "" {
		return fmt.Errorf("profiles: profile at index %d has empty name", i)
	}

	if _, exists := profileExist[pfName]; exists {
		return fmt.Errorf("profiles: duplicate profile name %q", pfName)
	}

	profileExist[pfName] = true

	if len(profile.Features) == 0 {
		return fmt.Errorf("profiles: profile %q has no features", pfName)
	}

	return nil
}
