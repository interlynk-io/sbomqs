/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/spf13/cobra"
)

const features_file_name = "features.yaml"
const features = "features"

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "provides a comprehensive config generate for your sbom to get specific criteria",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := logger.WithLogger(context.Background())

		if len(args) > 0 {
			if args[0] == features {
				return generateYaml(ctx)
			}
		} else {
			return fmt.Errorf(fmt.Sprintf("arguments missing%s", "list of valid command eg. features"))
		}
		return fmt.Errorf(fmt.Sprintf("invalid arguments%s", "list of valid command eg. features"))

	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

func generateYaml(ctx context.Context) error {
	return os.WriteFile(features_file_name, []byte(scorer.DefaultConfig()), 0755)
}
