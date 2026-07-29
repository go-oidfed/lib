package internal

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// zerologPkgPath is the import path of the rs/zerolog package. Frames coming
// from it (Event.Msg, Logger.Debug, ...) are skipped when resolving the caller
// so the reported location is the library call site rather than zerolog
// internals. It is derived from the actual compiled type so it stays correct
// across vendoring or module replacements.
var zerologPkgPath = reflect.TypeOf(zerolog.Event{}).PkgPath()

// internalPkgPath is this package's import path. It is skipped so that logging
// through the wrapper helpers below (Debug, Info, ...) reports the real caller
// instead of logging.go itself.
var internalPkgPath = reflect.TypeOf(libCallerHook{}).PkgPath()

// libCallerHook attaches the caller (file:line) to every emitted event. Unlike
// zerolog's built-in Caller(), which uses a single fixed stack skip, this hook
// walks the stack and picks the first frame outside of zerolog and this
// package. That yields the correct call site regardless of whether the log
// statement went through one of the wrapper helpers (Debug/Info/...) or
// directly through Logger().X()...Msg(), which require different skip counts.
//
// The caller is only recorded at debug level (mirroring the host application's
// convention of adding Caller() to its own logger only when debug is enabled),
// keeping library output consistent with the rest of the log stream.
type libCallerHook struct{}

func (libCallerHook) Run(e *zerolog.Event, _ zerolog.Level, _ string) {
	if zerolog.GlobalLevel() > zerolog.DebugLevel {
		return
	}
	var pcs [24]uintptr
	// Start just above this hook and runtime.Callers; package filtering below
	// handles the rest, so the exact skip is not load-bearing.
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if frame.Function != "" && !inPkgTree(frame.Function, zerologPkgPath) && !inPkgExact(frame.Function, internalPkgPath) {
			e.Str(zerolog.CallerFieldName, zerolog.CallerMarshalFunc(frame.PC, frame.File, frame.Line))
			return
		}
		if !more {
			return
		}
	}
}

// inPkgTree reports whether fn belongs to pkg or any of its subpackages. Used
// for the zerolog package, whose Event/Logger/log helpers (and subpackages)
// are all stack frames that must be skipped.
func inPkgTree(fn, pkg string) bool {
	return hasPkgPrefix(fn, pkg, true)
}

// inPkgExact reports whether fn belongs to pkg itself but not one of its
// subpackages. Used for this package: the wrapper helpers (Debug, Logger, ...)
// live here and must be skipped, but callers from internal/* subpackages (if
// any) are real call sites that should be reported.
func inPkgExact(fn, pkg string) bool {
	return hasPkgPrefix(fn, pkg, false)
}

func hasPkgPrefix(fn, pkg string, allowSubpkg bool) bool {
	if !strings.HasPrefix(fn, pkg) {
		return false
	}
	if len(fn) == len(pkg) {
		return true
	}
	c := fn[len(pkg)]
	return c == '.' || (allowSubpkg && c == '/')
}

// Package-private logger instance to keep logging isolated from applications.
// Uses zerolog with a console writer by default to match the previous logrus
// text output.
var logger = zerolog.New(
	zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	},
).
	Hook(libCallerHook{}).
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
