package engine

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestHandleURL(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedPath   string
		expectedRawURL string
		expectedError  bool
	}{
		{
			name:           "Valid URL",
			input:          "https://github.com/interlynk-io/sbomqs/blob/main/samples/sbomqs-spdx-syft.json",
			expectedPath:   "samples/sbomqs-spdx-syft.json",
			expectedRawURL: "https://raw.githubusercontent.com/interlynk-io/sbomqs/main/samples/sbomqs-spdx-syft.json",
			expectedError:  false,
		},
		{
			name:           "Valid URL with direct file",
			input:          "https://github.com/viveksahu26/go-url/blob/main/spdx.json",
			expectedError:  false,
			expectedPath:   "spdx.json",
			expectedRawURL: "https://raw.githubusercontent.com/viveksahu26/go-url/main/spdx.json",
		},
		{
			name:           "Invalid URL with not enough parts",
			input:          "https://github.com/interlynk-io/sbomqs/blob/main/",
			expectedPath:   "",
			expectedRawURL: "",
			expectedError:  true,
		},
		{
			name:           "Malformed URL",
			input:          "invalid-url",
			expectedPath:   "",
			expectedRawURL: "",
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sbomFilePath, rawURL, err := handleURL(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedPath, sbomFilePath)
				assert.Equal(t, tc.expectedRawURL, rawURL)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedPath, sbomFilePath)
				assert.Equal(t, tc.expectedRawURL, rawURL)
			}
		})
	}
}

// TestProcessURL function
func TestProcessURL(t *testing.T) {
	tests := []struct {
		name                 string
		url                  string
		statusCode           int
		expectedError        bool
		expectedErrorMessage error
	}{
		{
			name:                 "Successful download",
			url:                  "https://github.com/interlynk-io/sbomqs/blob/main/samples/sbomqs-spdx-syft.json",
			statusCode:           http.StatusOK,
			expectedError:        false,
			expectedErrorMessage: nil,
		},
		{
			name:                 "Failed to get data",
			url:                  "http://example.com/file.txt",
			statusCode:           http.StatusNotFound,
			expectedError:        true,
			expectedErrorMessage: fmt.Errorf("failed to download file: %s %s", "404", http.StatusText(http.StatusNotFound)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			file, err := fs.Create("testfile.txt")
			if err != nil {
				log.Fatalf("error: %v", err)
			}

			_, err = ProcessURL(tt.url, file)
			if tt.expectedError {
				assert.EqualError(t, err, tt.expectedErrorMessage.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
