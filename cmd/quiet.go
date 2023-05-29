package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var quietFlagValue bool

// quietCmd represents the quiet command
var quietCmd = &cobra.Command{
	Use:   "quiet",
	Short: "Use this to turn off all the console logger",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println(quietFlagValue)
	},
}

func init() {
	rootCmd.AddCommand(quietCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	quietCmd.PersistentFlags().BoolVarP(&quietFlagValue, "quiet", "q", true, "Use this to turn off all the console logger")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// quietCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
