/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/engine"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/samber/lo"

	"github.com/spf13/cobra"
)

var (
	inFile       string
	inDirPath    string
	category     string
	feature      string
	reportFormat string
	configPath   string
)

type userCmd struct {
	//input control
	path string

	//filter control
	category string
	features []string

	//output control
	json     bool
	basic    bool
	detailed bool

	//spec control
	spdx bool
	cdx  bool

	//directory control
	recurse bool

	//debug control
	debug bool

	//config control
	configPath string
}

// scoreCmd represents the score command
var scoreCmd = &cobra.Command{
	Use:          "score",
	Short:        "comprehensive quality score for your sbom",
	SilenceUsage: true,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) <= 0 {
			if len(inFile) <= 0 && len(inDirPath) <= 0 {
				return fmt.Errorf("provide a path to an sbom file or directory of sbom files")
			}

		} else if len(args) > 1 {
			return fmt.Errorf("too many arguments")
		}
		return nil
	},
	RunE: processScore,
}

func processScore(cmd *cobra.Command, args []string) error {
	debug, _ := cmd.Flags().GetBool("debug")
	if debug {
		logger.InitDebugLogger()
	} else {
		logger.InitProdLogger()
	}

	ctx := logger.WithLogger(context.Background())
	uCmd := toUserCmd(cmd, args)

	if err := validateFlags(uCmd); err != nil {
		return err
	}

	engParams := toEngineParams(uCmd)
	return engine.Run(ctx, engParams)
}
func toUserCmd(cmd *cobra.Command, args []string) *userCmd {
	uCmd := &userCmd{}

	//input control
	if len(args) <= 0 {
		if len(inFile) > 0 {
			uCmd.path = inFile
		}

		if len(inDirPath) > 0 {
			uCmd.path = inDirPath
		}
	} else {
		uCmd.path = args[0]
	}

	//config control
	if configPath == "" {
		uCmd.configPath, _ = cmd.Flags().GetString("configpath")
	} else {
		uCmd.configPath = configPath
	}
	//filter control
	if category == "" {
		uCmd.category, _ = cmd.Flags().GetString("category")
	} else {
		uCmd.category = category
	}

	if feature == "" {
		f, _ := cmd.Flags().GetString("feature")
		uCmd.features = strings.Split(f, ",")
	}

	//output control
	uCmd.json, _ = cmd.Flags().GetBool("json")
	uCmd.basic, _ = cmd.Flags().GetBool("basic")
	uCmd.detailed, _ = cmd.Flags().GetBool("detailed")

	if reportFormat != "" {
		uCmd.json = strings.ToLower(reportFormat) == "json"
		uCmd.basic = strings.ToLower(reportFormat) == "basic"
		uCmd.detailed = strings.ToLower(reportFormat) == "detailed"
	}

	//spec control
	// uCmd.spdx, _ = cmd.Flags().GetBool("spdx")
	// uCmd.cdx, _ = cmd.Flags().GetBool("cdx")

	//directory control
	//uCmd.recurse, _ = cmd.Flags().GetBool("recurse")

	//debug control
	uCmd.debug, _ = cmd.Flags().GetBool("debug")

	return uCmd
}

func toEngineParams(uCmd *userCmd) *engine.Params {
	return &engine.Params{
		Path:       uCmd.path,
		Category:   uCmd.category,
		Features:   uCmd.features,
		Json:       uCmd.json,
		Basic:      uCmd.basic,
		Detailed:   uCmd.detailed,
		Recurse:    uCmd.recurse,
		Debug:      uCmd.debug,
		ConfigPath: uCmd.configPath,
	}
}

func validatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return nil
}
func validateFlags(cmd *userCmd) error {
	if err := validatePath(cmd.path); err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	if cmd.configPath != "" {
		if err := validatePath(cmd.configPath); err != nil {
			return fmt.Errorf("invalid config path: %w", err)
		}
	}

	if len(reportFormat) > 0 && !lo.Contains(reporter.ReportFormats, reportFormat) {
		return fmt.Errorf("invalid report format: %s", reportFormat)
	}

	return nil
}
func init() {
	rootCmd.AddCommand(scoreCmd)

	//Config Control
	scoreCmd.Flags().StringP("configpath", "", "", "scoring based on config path")

	//Filter Control
	scoreCmd.Flags().StringP("category", "c", "", "filter by category")
	scoreCmd.Flags().StringP("feature", "f", "", "filter by feature")

	//Spec Control
	scoreCmd.Flags().BoolP("spdx", "", false, "limit scoring to spdx sboms")
	scoreCmd.Flags().BoolP("cdx", "", false, "limit scoring to cdx sboms")
	scoreCmd.MarkFlagsMutuallyExclusive("spdx", "cdx")
	scoreCmd.Flags().MarkHidden("spdx")
	scoreCmd.Flags().MarkHidden("cdx")

	//Directory Control
	scoreCmd.Flags().BoolP("recurse", "r", false, "recurse into subdirectories")
	scoreCmd.Flags().MarkHidden("recurse")

	//Output Control
	scoreCmd.Flags().BoolP("json", "j", false, "results in json")
	scoreCmd.Flags().BoolP("detailed", "d", false, "results in table format, default")
	scoreCmd.Flags().BoolP("basic", "b", false, "results in single line format")

	//Debug Control
	scoreCmd.Flags().BoolP("debug", "D", false, "enable debug logging")

	//Deprecated
	scoreCmd.Flags().StringVar(&inFile, "filepath", "", "sbom file path")
	scoreCmd.Flags().StringVar(&inDirPath, "dirpath", "", "sbom dir path")
	scoreCmd.MarkFlagsMutuallyExclusive("filepath", "dirpath")
	scoreCmd.Flags().StringVar(&reportFormat, "reportFormat", "", "reporting format basic/detailed/json")
	scoreCmd.Flags().MarkDeprecated("reportFormat", "use --json, --detailed, or --basic instead")
	scoreCmd.Flags().MarkDeprecated("filepath", "use positional argument instead")
	scoreCmd.Flags().MarkDeprecated("dirpath", "use positional argument instead")
}
