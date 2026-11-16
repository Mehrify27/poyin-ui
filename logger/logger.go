// Package logger provides logging functionality for the vpn-ui panel with
// dual-backend logging (console/syslog and file) and buffered log storage for web UI.
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/op/go-logging"
)

const (
	maxLogBufferSize = 10240                 // Maximum log entries kept in memory
	logFileName      = "vpn-ui.log"          // Log file name
	timeFormat       = "2006/01/02 15:04:05" // Log timestamp format
)

var (
	loggerMu sync.RWMutex
	logger   *logging.Logger
	logFile  *os.File

	bufMu sync.Mutex
	// logBuffer maintains recent log entries in memory for web UI retrieval
	logBuffer []struct {
		time  string
		level logging.Level
		log   string
	}
)

// InitLogger initializes dual logging backends: console/syslog and file.
// Console logging uses the specified level, file logging always uses DEBUG level.
func InitLogger(level logging.Level) {
	newLogger := logging.MustGetLogger("vpn-ui")
	backends := make([]logging.Backend, 0, 2)

	// Console/syslog backend with configurable level
	if consoleBackend := initDefaultBackend(); consoleBackend != nil {
		leveledBackend := logging.AddModuleLevel(consoleBackend)
		leveledBackend.SetLevel(level, "vpn-ui")
		backends = append(backends, leveledBackend)
	}

	// File backend with DEBUG level for comprehensive logging
	fileBackend, newFile := initFileBackend()
	if fileBackend != nil {
		leveledBackend := logging.AddModuleLevel(fileBackend)
		leveledBackend.SetLevel(logging.DEBUG, "vpn-ui")
		backends = append(backends, leveledBackend)
	}

	multiBackend := logging.MultiLogger(backends...)
	newLogger.SetBackend(multiBackend)

	loggerMu.Lock()
	oldFile := logFile
	if newFile != nil {
		logFile = newFile
	} else {
		logFile = nil
	}
	logger = newLogger
	loggerMu.Unlock()

	if oldFile != nil {
		_ = oldFile.Close()
	}
}

func activeLogger() *logging.Logger {
	loggerMu.RLock()
	l := logger
	loggerMu.RUnlock()
	return l
}

// initDefaultBackend creates the console/syslog logging backend.
// Attempts syslog, falls back to stderr.
func initDefaultBackend() logging.Backend {
	var backend logging.Backend
	includeTime := false

	if syslogBackend, err := logging.NewSyslogBackend(""); err != nil {
		fmt.Fprintf(os.Stderr, "syslog backend disabled: %v\n", err)
		backend = logging.NewLogBackend(os.Stderr, "", 0)
		includeTime = os.Getppid() > 0
	} else {
		backend = syslogBackend
	}

	return logging.NewBackendFormatter(backend, newFormatter(includeTime))
}

// initFileBackend creates the file logging backend and returns the opened file handle.
// Creates log directory and truncates log file on startup for fresh logs.
func initFileBackend() (logging.Backend, *os.File) {
	logDir := config.GetLogFolder()
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log folder %s: %v\n", logDir, err)
		return nil, nil
	}

	logPath := filepath.Join(logDir, logFileName)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o660)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open log file %s: %v\n", logPath, err)
		return nil, nil
	}

	backend := logging.NewLogBackend(file, "", 0)
	return logging.NewBackendFormatter(backend, newFormatter(true)), file
}

// newFormatter creates a log formatter with optional timestamp.
func newFormatter(withTime bool) logging.Formatter {
	format := `%{level} - %{message}`
	if withTime {
		format = `%{time:` + timeFormat + `} %{level} - %{message}`
	}
	return logging.MustStringFormatter(format)
}

// CloseLogger closes the log file and cleans up resources.
// Should be called during application shutdown.
func CloseLogger() {
	loggerMu.Lock()
	f := logFile
	logFile = nil
	loggerMu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// Debug logs a debug message and adds it to the log buffer.
func Debug(args ...any) {
	if l := activeLogger(); l != nil {
		l.Debug(args...)
	}
	addToBuffer("DEBUG", fmt.Sprint(args...))
}

// Debugf logs a formatted debug message and adds it to the log buffer.
func Debugf(format string, args ...any) {
	if l := activeLogger(); l != nil {
		l.Debugf(format, args...)
	}
	addToBuffer("DEBUG", fmt.Sprintf(format, args...))
}

// Info logs an info message and adds it to the log buffer.
func Info(args ...any) {
	if l := activeLogger(); l != nil {
		l.Info(args...)
	}
	addToBuffer("INFO", fmt.Sprint(args...))
}

// Infof logs a formatted info message and adds it to the log buffer.
func Infof(format string, args ...any) {
	if l := activeLogger(); l != nil {
		l.Infof(format, args...)
	}
	addToBuffer("INFO", fmt.Sprintf(format, args...))
}

// Notice logs a notice message and adds it to the log buffer.
func Notice(args ...any) {
	if l := activeLogger(); l != nil {
		l.Notice(args...)
	}
	addToBuffer("NOTICE", fmt.Sprint(args...))
}

// Noticef logs a formatted notice message and adds it to the log buffer.
func Noticef(format string, args ...any) {
	if l := activeLogger(); l != nil {
		l.Noticef(format, args...)
	}
	addToBuffer("NOTICE", fmt.Sprintf(format, args...))
}

// Warning logs a warning message and adds it to the log buffer.
func Warning(args ...any) {
	if l := activeLogger(); l != nil {
		l.Warning(args...)
	}
	addToBuffer("WARNING", fmt.Sprint(args...))
}

// Warningf logs a formatted warning message and adds it to the log buffer.
func Warningf(format string, args ...any) {
	if l := activeLogger(); l != nil {
		l.Warningf(format, args...)
	}
	addToBuffer("WARNING", fmt.Sprintf(format, args...))
}

// Error logs an error message and adds it to the log buffer.
func Error(args ...any) {
	if l := activeLogger(); l != nil {
		l.Error(args...)
	}
	addToBuffer("ERROR", fmt.Sprint(args...))
}

// Errorf logs a formatted error message and adds it to the log buffer.
func Errorf(format string, args ...any) {
	if l := activeLogger(); l != nil {
		l.Errorf(format, args...)
	}
	addToBuffer("ERROR", fmt.Sprintf(format, args...))
}

// addToBuffer adds a log entry to the in-memory ring buffer for web UI retrieval.
func addToBuffer(level string, newLog string) {
	t := time.Now()
	logLevel, _ := logging.LogLevel(level)

	bufMu.Lock()
	if len(logBuffer) >= maxLogBufferSize {
		logBuffer = logBuffer[1:]
	}
	logBuffer = append(logBuffer, struct {
		time  string
		level logging.Level
		log   string
	}{
		time:  t.Format(timeFormat),
		level: logLevel,
		log:   newLog,
	})
	bufMu.Unlock()
}

// GetLogs retrieves up to c log entries from the buffer that are at or below the specified level.
func GetLogs(c int, level string) []string {
	var output []string
	logLevel, _ := logging.LogLevel(level)

	bufMu.Lock()
	for i := len(logBuffer) - 1; i >= 0 && len(output) <= c; i-- {
		if logBuffer[i].level <= logLevel {
			output = append(output, fmt.Sprintf("%s %s - %s", logBuffer[i].time, logBuffer[i].level, logBuffer[i].log))
		}
	}
	bufMu.Unlock()
	return output
}
