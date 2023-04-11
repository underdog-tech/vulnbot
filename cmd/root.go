/*
Copyright © 2023 Pinwheel
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "dependabot-alert-bot",
	Short: "Vulnbot: Your all-in-one security alert manager. Stay informed about vulnerabilities in your code with this powerful bot that pulls in alerts from various sources and reports them to your preferred systems.",
	Long: `Vulnbot is a comprehensive security alert manager designed to keep your code safe from vulnerabilities. 
	
It is a versatile bot that can seamlessly integrate with multiple data sources, such as GitHub, and soon Phylum, 
to pull in security and vulnerability alerts in real-time. With its customizable alert filters, flexible reporting options, 
and easy-to-use CLI, Vulnbot empowers developers and security teams to efficiently manage and respond to security threats.`,
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
