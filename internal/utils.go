package internal

import (
	"vulnbot/logger"

	"github.com/spf13/pflag"
)

func checkErr(err error) {
	log := logger.Get()
	if err != nil {
		log.Info().Err(err).Msg("Unexpected error extracting the flag.")
	}
}

// getBool return the bool value of a flag with the given name
func getBool(flags *pflag.FlagSet, flag string) bool {
	b, err := flags.GetBool(flag)
	checkErr(err)
	return b
}
