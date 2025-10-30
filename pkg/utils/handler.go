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

package utils

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func IsDir(path string) bool {
	pathInfo, err := os.Stat(path)
	if err != nil {
		// log.Debugf("os.Stat failed for path:%s\n", path)
		// log.Infof("%s\n", err)
		return false
	}
	return pathInfo.IsDir()
}

// Set[T] is a generic "set" of values of type T.
// Internally it's a map[T]struct{}
type Set[T comparable] map[T]struct{}

// AppendUnique adds the value v to the slice pointed to by out **only if**
// it hasn't been seen before. "already" tracks which values were already added
func AppendUnique[T comparable](out *[]T, already Set[T], v T) bool {
	if _, ok := already[v]; ok {
		return false
	}
	*out = append(*out, v)
	already[v] = struct{}{}
	return true
}

func IsURL(in string) bool {
	return regexp.MustCompile("^(http|https)://").MatchString(in)
}

// IsBlank reports whether s is empty or only whitespace (Unicode-aware).
func IsBlank(s string) bool {
	return strings.TrimSpace(s) == ""
}

func RemoveEmptyStrings(input []string) []string {
	output := make([]string, 0, len(input))
	for _, in := range input {
		if trimmed := strings.TrimSpace(in); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	return output
}

func IsGit(in string) bool {
	return regexp.MustCompile("^(http|https)://github.com").MatchString(in)
}

func HandleURL(path string) (string, string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse urlPath: %w", err)
	}

	parts := strings.Split(u.Path, "/")
	containSlash := strings.HasSuffix(u.Path, "/")
	var sbomFilePath string

	if containSlash {
		if len(parts) < 7 {
			return "", "", fmt.Errorf("invalid GitHub URL: %v", path)
		}
		sbomFilePath = strings.Join(parts[5:len(parts)-1], "/")
	} else {
		if len(parts) < 6 {
			return "", "", fmt.Errorf("invalid GitHub URL: %v", path)
		}
		sbomFilePath = strings.Join(parts[5:], "/")
	}

	rawURL := strings.Replace(path, "github.com", "raw.githubusercontent.com", 1)
	rawURL = strings.Replace(rawURL, "/blob/", "/", 1)

	return sbomFilePath, rawURL, err
}

func DownloadSBOMFromURL(url string) ([]byte, error) {
	//nolint: gosec
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}
	defer resp.Body.Close()

	// Ensure the response is OK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download file: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("downloaded data is empty")
	}

	return data, err
}
