// Based on https://betterstack.com/community/guides/logging/zerolog/

package logger

import (
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

var once sync.Once
var log zerolog.Logger

func Get() zerolog.Logger {
	once.Do(func() {
		var logLevel int8

		zerolog.TimeFieldFormat = time.RFC3339Nano
		parsed, err := strconv.ParseInt(os.Getenv("LOG_LEVEL"), 10, 8)
		if err != nil {
			logLevel = int8(zerolog.InfoLevel) // Default to INFO
		} else {
			logLevel = int8(parsed)
		}

		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
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
