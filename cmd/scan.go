package cmd

import (
	"github.com/underdog-tech/vulnbot/internal"

	"github.com/spf13/cobra"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:     "scan",
	Short:   "",
	Long:    ``,
	Run:     internal.Scan,
	Aliases: []string{"s", "scan"},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
