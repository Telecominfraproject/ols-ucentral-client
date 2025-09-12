package logger

import (
	"fmt"
	"log"
	"log/syslog"
)

const Program = "ucentral-client"
const DefaultLogLevel = syslog.LOG_INFO

type LogLevel int

const (
	DebugLevel  = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var (
	writer *syslog.Writer
)

func init() {
	var err error
	writer, err = syslog.New(DefaultLogLevel, Program)
	if err != nil {
		log.Printf("failed to create syslog writer: %v", err)
	}
}

func Debug(format string, v ...interface{}) {
	logMessage(DebugLevel, format, v...)
}

func Info(format string, v ...interface{}) {
	logMessage(InfoLevel, format, v...)
}

func Warn(format string, v ...interface{}) {
	logMessage(WarnLevel, format, v...)
}

func Error(format string, v ...interface{}) {
	logMessage(ErrorLevel, format, v...)
}

func logMessage(level LogLevel, format string, v ...interface{}) {
	var prefix string
	switch level {
	case DebugLevel:
		prefix = "[DEBUG] "
	case InfoLevel:
		prefix = "[INFO] "
	case WarnLevel:
		prefix = "[WARN] "
	case ErrorLevel:
		prefix = "[ERROR] "
	}

	msg := fmt.Sprintf(format, v...)

	if writer == nil {
		log.Print(prefix + msg) // fallback to stdout
		return
	}

	switch level {
	case DebugLevel:
		if err := writer.Debug(msg); err != nil {
            log.Printf("Error: %s", err.Error())
        }
	case InfoLevel:
		if err := writer.Info(msg); err != nil {
            log.Printf("Error: %s", err.Error())
        }
	case WarnLevel:
		if err := writer.Warning(msg); err != nil {
            log.Printf("Error: %s", err.Error())
        }
	case ErrorLevel:
		if err := writer.Err(msg); err != nil {
            log.Printf("Error: %s", err.Error())
        }
	}
}
