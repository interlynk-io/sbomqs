// Copyright 2023 Interlynk.io
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

package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateFile(t *testing.T) {
	ctx := context.Background()

	// Test case: file does not exist
	filePath := "nonexistentfile.txt"
	file, err := ValidateFile(ctx, filePath)
	assert.Nil(t, file)
	assert.Error(t, err)
	assert.EqualError(t, err, fmt.Errorf("failed to stat %s", filePath).Error())

	// Test case: file successfully exists
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "file.txt")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	filePath = tempFile.Name()
	file, err = ValidateFile(ctx, filePath)
	assert.NoError(t, err)
	assert.NotNil(t, file)
	assert.FileExists(t, file.Name())
	file.Close()

	// Test case: file exists but cannot be opened
	tempFile, err = os.CreateTemp("", "testfile-unreadable")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	filePath = tempFile.Name()
	err = os.Chmod(filePath, 0o222) // Make the file write-only to cause open error
	assert.NoError(t, err)

	file, err = ValidateFile(ctx, filePath)
	assert.Nil(t, file)
	assert.Error(t, err)
	assert.EqualError(t, err, fmt.Errorf("failed to open %s", filePath).Error())

	// Restore file permissions to delete the temp file
	os.Chmod(filePath, 0o644)
}

// TestHandlePaths tests the HandlePaths function
func TestHandlePaths(t *testing.T) {
	ctx := context.Background()

	baseDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(baseDir)

	file1 := filepath.Join(baseDir, "file1.txt")
	err = os.WriteFile(file1, []byte("content1"), 0o644)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}

	subDir := filepath.Join(baseDir, "subdir")
	err = os.Mkdir(subDir, 0o755)
	if err != nil {
		t.Fatalf("Failed to create temporary subdirectory: %v", err)
	}

	file2 := filepath.Join(subDir, "file2.txt")
	err = os.WriteFile(file2, []byte("content2"), 0o644)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}

	// Test case: directory containing sub-dir and files
	paths := []string{baseDir}
	expectedPaths := []string{file1, file2}
	allFilesPath := HandlePaths(ctx, paths)
	assert.NotNil(t, allFilesPath)
	assert.ElementsMatch(t, expectedPaths, allFilesPath)

	// Test case: non-existent path
	nonExistentPath := "/nonexistent"
	paths = []string{nonExistentPath}
	allFilesPath = HandlePaths(ctx, paths)
	assert.Empty(t, allFilesPath)

	// Test case: single file path
	singleFilePath := file1
	paths = []string{singleFilePath}
	expectedPaths = []string{singleFilePath}
	allFilesPath = HandlePaths(ctx, paths)
	assert.ElementsMatch(t, expectedPaths, allFilesPath)
}

func TestGetDocsAndScore(t *testing.T) {
	ctx := context.Background()
	params := &Params{}
	path := "../../samples/sbomqs-spdx-syft.json"
	file, err := ValidateFile(ctx, path)
	assert.NoError(t, err)

	doc, score, err := GetDocsAndScore(ctx, file, params)
	assert.NotNil(t, doc)
	assert.NoError(t, err)
	assert.NotNil(t, score)

	expectedAvgScore := 6.4
	actualAvgScore := fmt.Sprintf("%0.1f", score.AvgScore())
	fmt.Println("actualAvgScore: ", actualAvgScore)
	assert.Equal(t, fmt.Sprintf("%0.1f", expectedAvgScore), actualAvgScore)
}

func TestGetDocsAndScoreWithError(t *testing.T) {
	ctx := context.Background()
	params := &Params{}

	path := "../../samples/sbomqs-spdx-syft.json"
	file, err := ValidateFile(ctx, path)
	assert.NoError(t, err)

	// on closing file will lead to pass closed file in GetDocsAndScoreet
	file.Close()

	doc, score, err := GetDocsAndScore(ctx, file, params)
	assert.Nil(t, doc)
	assert.Error(t, err)
	assert.Nil(t, score)

	expectedErr := fmt.Errorf("unsupported sbom format")
	assert.EqualError(t, err, expectedErr.Error())
}
