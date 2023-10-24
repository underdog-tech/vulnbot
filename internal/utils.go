package internal

import (
	"path"
	"path/filepath"
	"runtime"

	"github.com/underdog-tech/vulnbot/logger"

	"github.com/spf13/pflag"
)

func checkErr(err error) {
	log := logger.Get()
	if err != nil {
		log.Fatal().Err(err).Msg("Unexpected error extracting the flag.")
	}
}

// getString return the string value of a flag with the given name
func getString(flags *pflag.FlagSet, flag string) string {
	s, err := flags.GetString(flag)
	checkErr(err)
	return s
}

// getStringSlice return the []string value of a flag with the given name
func getStringSlice(flags *pflag.FlagSet, flag string) []string {
	s, err := flags.GetStringSlice(flag)
	checkErr(err)
	return s
}

// GetProjectRootDir retrieves the root directory of the project
func GetProjectRootDir() string {
	// Retrieve information about the caller
	_, callerFile, _, _ := runtime.Caller(0)
	callerDir := path.Join(path.Dir(callerFile))
	parentDir := filepath.Dir(callerDir)
	return parentDir
}

// stringInSlice checks if a string exists in a slice of strings.
// It returns true if the string is found in the slice, and false otherwise.
func stringInSlice(s string, slice []string) bool {
    for _, item := range slice {
        if item == s {
            return true
        }
    }
    return false
}
