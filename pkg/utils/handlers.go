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

var ValidateFeatures = map[string]bool{
	"comp_with_name":                 true,
	"comp_with_version":              true,
	"comp_with_supplier":             true,
	"comp_with_uniq_ids":             true,
	"comp_valid_licenses":            true,
	"comp_with_any_vuln_lookup_id":   true,
	"comp_with_deprecated_licenses":  true,
	"comp_with_multi_vuln_lookup_id": true,
	"comp_with_primary_purpose":      true,
	"comp_with_restrictive_licenses": true,
	"comp_with_checksums":            true,
	"comp_with_licenses":             true,
	"comp_with_checksums_sha256":     true,
	"comp_with_source_code_uri":      true,
	"comp_with_source_code_hash":     true,
	"comp_with_executable_uri":       true,
	// "comp_with_executable_hash":      true,

	"comp_with_associated_license": true,
	"comp_with_concluded_license":  true,
	"comp_with_declared_license":   true,

	"sbom_creation_timestamp":       true,
	"sbom_authors":                  true,
	"sbom_with_creator_and_version": true,
	"sbom_with_primary_component":   true,
	"sbom_dependencies":             true,
	"sbom_sharable":                 true,
	"sbom_parsable":                 true,
	"sbom_spec":                     true,
	"sbom_file_format":              true,
	"sbom_spec_version":             true,
	"spec_with_version_compliant":   true,
	"sbom_with_uri":                 true,
	"sbom_with_vuln":                true,
	"sbom_build_process":            true,
	"sbom_with_bomlinks":            true,
	// "sbom_with_signature":           true,
}

var CategoryAliases = map[string]string{
	"ntia":                  "NTIA-minimum-elements",
	"NTIA":                  "NTIA-minimum-elements",
	"ntia-minimum-elements": "NTIA-minimum-elements",
	"structural":            "Structural",
	"sharing":               "Sharing",
	"semantic":              "Semantic",
	"quality":               "Quality",
}

var SupportedCategories = map[string]bool{
	"NTIA-minimum-elements": true,
	"Structural":            true,
	"Sharing":               true,
	"Semantic":              true,
	"Quality":               true,
	"bsi-v1.1":              true,
	"bsi-v2.0":              true,
}

func IsDir(path string) bool {
	pathInfo, err := os.Stat(path)
	if err != nil {
		// log.Debugf("os.Stat failed for path:%s\n", path)
		// log.Infof("%s\n", err)
		return false
	}
	return pathInfo.IsDir()
}

func IsURL(in string) bool {
	return regexp.MustCompile("^(http|https)://").MatchString(in)
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

func DownloadURL(url string) ([]byte, error) {
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
