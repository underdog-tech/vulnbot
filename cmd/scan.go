/*
Copyright © 2023 Pinwheel
*/
package cmd

import (
	"dependabot-alert-bot/pkg"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run:     pkg.Scan,
	Aliases: []string{"s", "scan"},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
