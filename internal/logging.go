package internal

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Package-private logger instance to keep logging isolated from applications.
// Uses zerolog with a console writer by default to match the previous logrus
// text output.
var logger = zerolog.New(
	zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	},
).
	With().
	Timestamp().
	Logger()

// EnableDebugLogging sets the logger level to Debug.
// Kept for backwards compatibility with existing tests.
func EnableDebugLogging() { // skipcq: RVV-B0001
	logger = logger.Level(zerolog.DebugLevel)
}

// DisableDebugLogging disables the logger so no logs are emitted.
func DisableDebugLogging() { // skipcq: RVV-B0001
	logger = logger.Level(zerolog.Disabled)
}

// SetLevel allows callers to control the library logger level independently
// from any application loggers.
func SetLevel(level zerolog.Level) {
	logger = logger.Level(level)
}

// SetOutput allows redirecting log output.
func SetOutput(w io.Writer) { // skipcq: RVV-B0001
	logger = logger.Output(w)
}

// Logger exposes the underlying logger for advanced configuration or chaining.
// Do not replace the returned value's fields; prefer Set* helpers.
func Logger() *zerolog.Logger { // skipcq: RVV-B0001
	return &logger
}

// Log logs a debug-level message.
func Log(v ...any) { // skipcq: RVV-B0001
	logger.Debug().Msg(fmt.Sprint(v...))
}

// Logf logs a formatted debug-level message.
func Logf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Debug().Msgf(format, v...)
}

// Debug logs a debug-level message.
func Debug(v ...any) { // skipcq: RVV-B0001
	logger.Debug().Msg(fmt.Sprint(v...))
}

// Debugf logs a formatted debug-level message.
func Debugf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Debug().Msgf(format, v...)
}

// Info logs an info-level message.
func Info(v ...any) { // skipcq: RVV-B0001
	logger.Info().Msg(fmt.Sprint(v...))
}

// Infof logs a formatted info-level message.
func Infof(format string, v ...any) { // skipcq: RVV-B0001
	logger.Info().Msgf(format, v...)
}

// Warn logs a warn-level message.
func Warn(v ...any) { // skipcq: RVV-B0001
	logger.Warn().Msg(fmt.Sprint(v...))
}

// Warnf logs a formatted warn-level message.
func Warnf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Warn().Msgf(format, v...)
}

// Error logs an error-level message.
func Error(v ...any) { // skipcq: RVV-B0001
	logger.Error().Msg(fmt.Sprint(v...))
}

// Errorf logs a formatted error-level message.
func Errorf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Error().Msgf(format, v...)
}
