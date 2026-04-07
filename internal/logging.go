package internal

import (
	"io"

	"github.com/sirupsen/logrus"
)

// Package-private logger instance to keep logging isolated from applications
// that also use logrus. Do NOT use logrus.StandardLogger() here.
var logger = logrus.New()

// EnableDebugLogging sets the logger level to Debug.
// Kept for backwards compatibility with existing tests.
func EnableDebugLogging() { // skipcq: RVV-B0001
	logger.SetLevel(logrus.DebugLevel)
}

// DisableDebugLogging sets the logger level to Panic so no debug/info logs are emitted.
func DisableDebugLogging() { // skipcq: RVV-B0001
	logger.SetLevel(logrus.PanicLevel)
}

// SetLevel allows callers to control the library logger level independently
// from any application loggers.
func SetLevel(level logrus.Level) {
	logger.SetLevel(level)
}

// SetOutput allows redirecting log output.
func SetOutput(w io.Writer) { // skipcq: RVV-B0001
	logger.SetOutput(w)
}

// SetFormatter allows customizing the log formatter.
func SetFormatter(f logrus.Formatter) { // skipcq: RVV-B0001
	logger.SetFormatter(f)
}

// Logger exposes the underlying logger for advanced configuration or hooks.
// Do not replace the returned pointer's value; prefer Set* helpers.
func Logger() *logrus.Logger { // skipcq: RVV-B0001
	return logger
}

// Log logs a debug-level message.
func Log(v ...any) { // skipcq: RVV-B0001
	logger.Debug(v...)
}

// Logf logs a formatted debug-level message.
func Logf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Debugf(format, v...)
}

// Debug logs a debug-level message.
func Debug(v ...any) { // skipcq: RVV-B0001
	logger.Debug(v...)
}

// Debugf logs a formatted debug-level message.
func Debugf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Debugf(format, v...)
}

// Info logs an info-level message.
func Info(v ...any) { // skipcq: RVV-B0001
	logger.Info(v...)
}

// Infof logs a formatted info-level message.
func Infof(format string, v ...any) { // skipcq: RVV-B0001
	logger.Infof(format, v...)
}

// Warn logs a warn-level message.
func Warn(v ...any) { // skipcq: RVV-B0001
	logger.Warn(v...)
}

// Warnf logs a formatted warn-level message.
func Warnf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Warnf(format, v...)
}

// Error logs an error-level message.
func Error(v ...any) { // skipcq: RVV-B0001
	logger.Error(v...)
}

// Errorf logs a formatted error-level message.
func Errorf(format string, v ...any) { // skipcq: RVV-B0001
	logger.Errorf(format, v...)
}

// WithError attaches an error to the entry for structured logging.
func WithError(err error) *logrus.Entry { // skipcq: RVV-B0001
	return logger.WithError(err)
}

// WithField attaches a key/value field to the entry for structured logging.
func WithField(key string, value any) *logrus.Entry { // skipcq: RVV-B0001
	return logger.WithField(key, value)
}

// WithFields attaches multiple fields to the entry for structured logging.
func WithFields(fields logrus.Fields) *logrus.Entry { // skipcq: RVV-B0001
	return logger.WithFields(fields)
}

// Fields is an alias exported to allow callers to construct structured fields
// without importing logrus directly when using the internal logger helpers.
// This keeps compatibility with existing call sites like
// `log.WithFields(log.Fields{...})` even after switching imports to this
// package.
type Fields = logrus.Fields
