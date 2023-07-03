// Based on https://betterstack.com/community/guides/logging/zerolog/

package logger

import (
	"io"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const DEFAULT_LOG_LEVEL = zerolog.WarnLevel

var lock = sync.Mutex{}
var log zerolog.Logger
var once sync.Once

func Get() zerolog.Logger {
	once.Do(func() {
		zerolog.TimeFieldFormat = time.RFC3339Nano
		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}

		buildInfo, _ := debug.ReadBuildInfo()
		log = zerolog.New(output).
			With().
			Timestamp().
			Str("go_version", buildInfo.GoVersion).
			Logger()
	})

	return log
}

func SetLogLevel(logLevel zerolog.Level) zerolog.Logger {
	lock.Lock()
	log := Get()
	zerolog.SetGlobalLevel(logLevel)
	log = log.Level(logLevel)
	lock.Unlock()
	return log
}
