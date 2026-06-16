// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateYamlDefaultsToV2FeaturesConfig(t *testing.T) {
	dir := chdirTemp(t)

	if err := generateYaml(context.Background(), false); err != nil {
		t.Fatalf("generateYaml() error = %v", err)
	}

	got := readGeneratedFeatures(t, dir)
	for _, want := range []string{
		"version: 2.0.0",
		"key: identification",
		"key: provenance",
		"key: integrity",
		"key: licensing_and_compliance",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated features config missing %q:\n%s", want, got)
		}
	}

	for _, legacy := range []string{
		"version: 1.0.0",
		"name: NTIA-minimum-elements",
		"name: bsi-v1.1",
	} {
		if strings.Contains(got, legacy) {
			t.Fatalf("generated features config contains legacy value %q:\n%s", legacy, got)
		}
	}
}

func TestGenerateYamlLegacyFeaturesConfig(t *testing.T) {
	dir := chdirTemp(t)

	if err := generateYaml(context.Background(), true); err != nil {
		t.Fatalf("generateYaml() error = %v", err)
	}

	got := readGeneratedFeatures(t, dir)
	for _, want := range []string{
		"version: 1.0.0",
		"name: NTIA-minimum-elements",
		"name: bsi-v1.1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated legacy features config missing %q:\n%s", want, got)
		}
	}

	if strings.Contains(got, "key: identification") {
		t.Fatalf("generated legacy features config contains v2 category key:\n%s", got)
	}
}

func TestGenerateFeaturesLegacyFlagIsRegistered(t *testing.T) {
	if generateCmd.Flags().Lookup("legacy") == nil {
		t.Fatal("generate command does not define --legacy flag")
	}
}

func chdirTemp(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir(%q) error = %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory %q: %v", wd, err)
		}
	})

	return dir
}

func readGeneratedFeatures(t *testing.T, dir string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(dir, featuresFileName))
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", featuresFileName, err)
	}
	return string(data)
}
