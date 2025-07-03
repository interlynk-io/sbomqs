package sbomqs

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

// validatePaths returns the valid paths.
func validatePaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debug("validating paths")
	var validPaths []string
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			log.Debugf("skipping invalid path: %s, error: %v", path, err)
			continue
		}
		validPaths = append(validPaths, path)
	}
	return validPaths
}

func validateConfig(ctx context.Context, config *Config) error {
	log := logger.FromContext(ctx)
	log.Debug("validating configuration")

	if config.ConfigFile != "" {
		if _, err := os.Stat(config.ConfigFile); err != nil {
			return fmt.Errorf("invalid config path: %s: %w", config.ConfigFile, err)
		}
	}
	config.Categories = removeEmptyStrings(config.Categories)

	if len(config.Categories) > 0 {
		log.Debugf("validating categories: %v", config.Categories)
		normCategories, err := normalizeAndValidateCategories(ctx, config.Categories)
		if err != nil {
			return fmt.Errorf("failed to normalize and validate categories: %w", err)
		}
		config.Categories = normCategories
	}

	config.Features = removeEmptyStrings(config.Features)
	if len(config.Features) > 0 {
		log.Debugf("validating features: %v", config.Features)
		validFeatures, err := validateFeatures(ctx, config.Features)
		if err != nil {
			return fmt.Errorf("failed to validate features: %w", err)
		}
		config.Features = validFeatures
	}

	return nil
}

func validateFeatures(ctx context.Context, features []string) ([]string, error) {
	log := logger.FromContext(ctx)
	var validFeatures []string

	for _, feature := range features {
		if _, ok := utils.ValidateFeatures[feature]; !ok {
			log.Warnf("unsupported feature: %s", feature)
			continue
		}
		validFeatures = append(validFeatures, feature)
	}
	return validFeatures, nil
}
