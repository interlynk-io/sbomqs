package sbomqs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

func processSBOMDocument(ctx context.Context, sbomFile *os.File, sig sbom.Signature) (sbom.Document, error) {
	log := logger.FromContext(ctx)

	doc, err := sbom.NewSBOMDocument(ctx, sbomFile, sig)
	if err != nil {
		log.Debugf("%s\n", err)
		return nil, err
	}
	return doc, nil
}

func getSignature(ctx context.Context, path string, sigValue, publicKey string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

	if sigValue == "" || publicKey == "" {
		return sbom.Signature{}, nil
	}
	blob, signature, pubKey, err := common.GetSignatureBundle(ctx, path, sigValue, publicKey)
	if err != nil {
		log.Debugf("failed to get signature bundle for file: %s: %v", path, err)
		return sbom.Signature{}, err
	}

	return sbom.Signature{
		SigValue:  signature,
		PublicKey: pubKey,
		Blob:      blob,
	}, nil
}

func getFileHandle(ctx context.Context, path string) (*os.File, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Opening file: %s", path)

	if _, err := os.Stat(path); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", path)
		fmt.Printf("failed to stat %s\n", path)
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		log.Debugf("Failed to open file: %s: %v", path, err)
		return nil, fmt.Errorf("failed to open file: %s: %w", path, err)
	}
	return f, nil
}

func processDirectory(ctx context.Context, dirPath string, config Config) []ScoreResult {
	log := logger.FromContext(ctx)
	log.Debugf("Processing directory: %s", dirPath)

	var results []ScoreResult

	files, _ := os.ReadDir(dirPath)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fullPath := filepath.Join(dirPath, f.Name())
		sbomFile, err := getFileHandle(ctx, fullPath)
		if err != nil {
			continue
		}
		sig, _ := getSignature(ctx, fullPath, config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey)
		result, err := processSBOMInput(ctx, sbomFile, sig, config, fullPath)
		if err == nil {
			results = append(results, result)
		}
	}
	return results
}

func processURLInput(ctx context.Context, url string, config Config) (*os.File, sbom.Signature, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing URL: %s", url)

	if utils.IsGit(url) {
		_, rawURL, err := utils.HandleURL(url)
		if err != nil {
			return nil, sbom.Signature{}, fmt.Errorf("handleURL failed: %w", err)
		}
		url = rawURL
	}

	// download SBOM data from the URL
	data, err := utils.DownloadURL(url)
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to download SBOM from URL %s: %w", url, err)
	}

	// create a temporary file to store the SBOM
	tmpFile, err := os.CreateTemp("", "sbomqs-url-*.json")
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to create temp file for SBOM: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to write to temp SBOM file: %w", err)
	}

	// Rewind file pointer for reading later
	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to reset temp file pointer: %w", err)
	}

	sig := sbom.Signature{
		SigValue:  config.SignatureBundle.SigValue,
		PublicKey: config.SignatureBundle.PublicKey,
	}

	return tmpFile, sig, nil
}

func normalizeAndValidateCategories(ctx context.Context, categories []string) ([]string, error) {
	log := logger.FromContext(ctx)
	var normalized []string

	for _, c := range categories {

		// normalize using alias
		if alias, ok := utils.CategoryAliases[c]; ok {
			c = alias
		}

		// validate if it's a supported category
		if !utils.SupportedCategories[c] {
			log.Warnf("unsupported category: %s", c)
			continue
		}

		normalized = append(normalized, c)
	}

	return normalized, nil
}
