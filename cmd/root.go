package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnbot",
	Short: "Vulnbot: Your all-in-one security alert manager.",
	Long: `Vulnbot is a comprehensive security alert manager designed to keep your code safe from vulnerabilities. 

It is a versatile bot that can seamlessly integrate with multiple data sources, such as GitHub, and soon Phylum, 
Vulnbot empowers developers and security teams to efficiently manage and respond to security threats.`,
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
