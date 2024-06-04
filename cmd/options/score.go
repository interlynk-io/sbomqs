package options

import (
	"github.com/spf13/cobra"
)

type ScoreOptions struct {
	// filter control
	Category string
	Features []string

	// output control
	Json     bool
	Basic    bool
	Detailed bool

	// directory control
	Recurse bool

	// debug control
	Debug bool

	// config control
	ConfigPath string
}

// AddFlags implements Interface
func (o *ScoreOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&o.Features, "features", "f", nil, "filter by category")
	cmd.Flags().StringVarP(&o.Category, "category", "c", "", "filter by category")
	cmd.Flags().StringVar(&o.ConfigPath, "configPath", "", "scoring based on config path")
	cmd.Flags().BoolVarP(&o.Json, "json", "j", false, "results in json")
	cmd.Flags().BoolVarP(&o.Basic, "basic", "b", false, "results in single line format")
	cmd.Flags().BoolVarP(&o.Detailed, "detailed", "d", true, "results in table format, default")
	cmd.Flags().BoolVarP(&o.Debug, "debug", "D", false, "enable debug logging")
	cmd.Flags().BoolVarP(&o.Recurse, "recurse", "r", false, "recurse into subdirectories")
}
