package oidfed

import (
	"io"

	"github.com/rs/zerolog"

	"github.com/go-oidfed/lib/internal"
)

// EnableDebugLogging enables debug logging
func EnableDebugLogging() {
	internal.EnableDebugLogging()
}

// DisableDebugLogging disables debug logging
func DisableDebugLogging() {
	internal.DisableDebugLogging()
}

// SetLogLevel sets the log level for the library's logger independently
// from any application loggers.
func SetLogLevel(level zerolog.Level) {
	internal.SetLevel(level)
}

// SetLogOutput sets the output writer for the library's logger.
func SetLogOutput(w io.Writer) {
	internal.SetOutput(w)
}
