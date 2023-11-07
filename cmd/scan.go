package cmd

import (
	"github.com/underdog-tech/vulnbot/internal"

	"github.com/spf13/cobra"
)

// NewScanCommand returns a Cobra command for running scans
func NewScanCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "scan",
		Short:   "",
		Long:    ``,
		Run:     internal.Scan,
		Aliases: []string{"s", "scan"},
	}
}
