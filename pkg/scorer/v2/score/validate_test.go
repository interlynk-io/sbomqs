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

package score

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAndExpandPaths_EmptyPath(t *testing.T) {
	ctx := context.Background()

	inputPaths := []string{
		"   ",
		"",
	}
	got := validateAndExpandPaths(ctx, inputPaths, false)
	assert.Empty(t, got)
}

func TestValidateAndExpandPaths_UrlsPreserved(t *testing.T) {
	ctx := context.Background()

	inputPaths := []string{
		"https://github.com/interlynk-io/sbomqs/v2/v2",
		"http://github.com/xyz",
	}
	got := validateAndExpandPaths(ctx, inputPaths, false)

	expected := []string{
		"http://github.com/xyz",
		"https://github.com/interlynk-io/sbomqs/v2/v2",
	}

	sort.Strings(got)
	sort.Strings(expected)

	assert.Equal(t, expected, got)
}

func TestValidateAndExpandPaths_ValidFilePaths_TempDir(t *testing.T) {
	ctx := context.Background()
	td := t.TempDir()

	f1 := filepath.Join(td, "sbom1.json")
	if err := os.WriteFile(f1, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sbom1.json: %v", err)
	}

	f2 := filepath.Join(td, "sbom2.json")
	if err := os.WriteFile(f2, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write sbom2.json: %v", err)
	}

	inputPaths := []string{f1, f2}
	got := validateAndExpandPaths(ctx, inputPaths, false)

	expected := []string{f1, f2}
	sort.Strings(expected)
	sort.Strings(got)

	assert.Equal(t, expected, got)
}

func TestValidateAndExpandPaths_InvalidFilePaths(t *testing.T) {
	ctx := context.Background()

	inputPaths := []string{
		"this-file-does-not-exist.txt",
		"/tmp/definitely-not-a-file.txt",
	}

	got := validateAndExpandPaths(ctx, inputPaths, false)

	assert.Empty(t, got)
}

func TestValidateAndExpandPaths_FileAndDirExpansion(t *testing.T) {
	ctx := context.Background()
	parentDir := t.TempDir()

	// create a file f1 under `parentDir` dir
	f1 := filepath.Join(parentDir, "sbom1.json")
	if err := os.WriteFile(f1, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write sbom1.json: %v", err)
	}

	// create a sub-dir `sub` under `td` dir
	sub := filepath.Join(parentDir, "subdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested.json"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write nested: %v", err)
	}

	// create a file f2 under `parentDir` dir
	f2 := filepath.Join(parentDir, "sbom2.json")
	if err := os.WriteFile(f2, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write sbom2: %v", err)
	}

	in := []string{parentDir, f1}
	got := validateAndExpandPaths(ctx, in, false)

	// build expected - expansion of `parendDir` includes file1 and file2 (nested file in subdir should NOT be included)
	expected := []string{f1, f2}
	sort.Strings(expected)
	sort.Strings(got)

	assert.Equal(t, expected, got)
}

func TestValidateAndExpandPaths_RecursiveDir(t *testing.T) {
	ctx := context.Background()
	parentDir := t.TempDir()

	// create a sub-dir `sub1` under `parentDir` dir
	temp1 := filepath.Join(parentDir, "temp1")
	if err := os.Mkdir(temp1, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	f3 := filepath.Join(temp1, "sbom3.json")
	if err := os.WriteFile(f3, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write sbom3: %v", err)
	}

	// create a sub-dir `sub2` under `parentDir` dir
	temp2 := filepath.Join(parentDir, "temp2")
	if err := os.Mkdir(temp2, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	f4 := filepath.Join(temp2, "sbom4.json")
	if err := os.WriteFile(f4, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write sbom4: %v", err)
	}

	in := []string{parentDir}

	// recursive == true
	got := validateAndExpandPaths(ctx, in, true)

	// build expected - recursive expansion of `parentDir`
	// includes files from nested sub-directories(`temp1` and `temp2`)
	expected := []string{f3, f4}
	sort.Strings(expected)
	sort.Strings(got)

	assert.Equal(t, expected, got)
}
