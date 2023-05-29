package cmd

import (
	"github.com/underdog-tech/vulnbot/logger"

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
	if !quietFlagValue {
		log := logger.Get()

		err := rootCmd.Execute()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to execute command.")
		}
	}
}

func init() {
	persistent := rootCmd.PersistentFlags()
	persistent.BoolP("disable-slack", "d", false, "Disable Slack alerts.")
	persistent.StringP("config", "c", "config.toml", "Config file path.")
}
