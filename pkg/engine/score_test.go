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
