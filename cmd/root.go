/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sbomqs",
	Short: "sbomqs application provides sbom quality scores.",
	Long: `SBOM Quality Score (sbomqs) is a standardized metric to 
produce a calculated score that represents a level of “quality” 
when using an SBOM. The sbomqs is intended to help customers make 
an assessment of a SBOM acceptance risk based on their personal risk tolerance.  
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
