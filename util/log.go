package util

import (
	"bytes"
	"io"
	"log"
)

type LogLevel byte

const (
	LogLevelTrace LogLevel = 0
	LogLevelDebug LogLevel = 1
	LogLevelEnabled LogLevel = 2
)

// Not sure if there is a standard library way to do this,
// but I couldn't find any at the moment
type logBuffer struct {
	buffer *bytes.Buffer
	output io.Writer
}

func newLogBuffer() *logBuffer {
	return &logBuffer{
		buffer: new(bytes.Buffer),
		output: nil,
	}
}

func (logBuf *logBuffer) Write(p []byte) (n int, err error) {
	if logBuf.output == nil {
		return logBuf.buffer.Write(p)
	} else {
		return logBuf.output.Write(p)
	}
}

func (logBuf *logBuffer) setOutput(output io.Writer) {
	if logBuf.buffer.Len() > 0 {
		b, _ := io.ReadAll(logBuf.buffer)
		output.Write(b)
	}
	logBuf.output = output
}

var enabledLogOutput *logBuffer = newLogBuffer()
var debugLogOutput *logBuffer = newLogBuffer()
var traceLogOutput *logBuffer = newLogBuffer()

func SetLogOutput(out io.Writer) {
	enabledLogOutput.setOutput(out)
}

func SetLogLevel(level LogLevel) {
	if level <= LogLevelTrace {
		traceLogOutput.setOutput(debugLogOutput)
	}
	if level <= LogLevelDebug {
		debugLogOutput.setOutput(enabledLogOutput)
	}
}

func NewLogger(prefix string, level LogLevel) *log.Logger {
	if level == LogLevelEnabled {
		return log.New(enabledLogOutput, prefix, 0)
	} else if level == LogLevelDebug {
		return log.New(debugLogOutput, prefix, 0)
	} else {
		return log.New(traceLogOutput, prefix, 0)
	}
}
