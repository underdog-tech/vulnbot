// Based on https://betterstack.com/community/guides/logging/zerolog/

package logger

import (
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/rs/zerolog"
)

var once sync.Once
var log zerolog.Logger

func Get() zerolog.Logger {
	once.Do(func() {
		logLevel, err := strconv.ParseInt(os.Getenv("LOG_LEVEL"), 10, 64)
		if err != nil {
			logLevel = int64(zerolog.InfoLevel) // Default to INFO
		}

		var output io.Writer = zerolog.ConsoleWriter{
			Out: os.Stdout,
		}

		buildInfo, _ := debug.ReadBuildInfo()
		log = zerolog.New(output).
			Level(zerolog.Level(logLevel)).
			With().
			Timestamp().
			Str("go_version", buildInfo.GoVersion).
			Logger()
	})

	return log
}
