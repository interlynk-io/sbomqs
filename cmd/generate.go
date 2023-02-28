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
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
			if args[0] == features{
				return generateYaml(ctx)
			}
		}else{
			return fmt.Errorf(fmt.Sprintf("arguments missing%s","list of valid command eg. features"))
		}
		return fmt.Errorf(fmt.Sprintf("invalid arguments%s","list of valid command eg. features"))

	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}

type Record struct {
	Name     string     `yaml:"name" json:"name"`
	Enabled  bool       `yaml:"enabled" json:"enabled"`
	Criteria []criteria `yaml:"criteria" json:"criteria"`
}

type criteria struct {
	Name        string `yaml:"shortName" json:"shortName"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

type Config struct {
	Record []Record `yaml:"category" json:"category"`
}

func generateYaml(ctx context.Context) error {
	cnf := Config{}
	for _, category := range scorer.Categories {
		record := Record{
			Name:    category,
			Enabled: true,
		}
		if len(scorer.CategorieMapWithCriteria(category)) > 0 {
			for _, crita := range scorer.CategorieMapWithCriteria(category) {
				record.Criteria = append(record.Criteria, criteria{
					Name:        (string(lo.Invert(scorer.CriteriaArgMap)[crita])),
					Description: crita,
					Enabled:     true,
				})
			}
		}
		cnf.Record = append(cnf.Record, record)

	}
	buf, err := yaml.Marshal(&cnf)
	if err != nil {
		return err
	}
	err = os.WriteFile(features_file_name, buf, 0755)
	return err
}

