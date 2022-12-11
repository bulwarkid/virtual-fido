package virtual_fido

import (
	"bytes"
	"io"
	"log"
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

var logOutput *logBuffer = newLogBuffer()

func SetLogOutput(out io.Writer) {
	logOutput.setOutput(out)
}

func newLogger(prefix string, enabled bool) *log.Logger {
	if enabled {
		return log.New(logOutput, prefix, 0)
	} else {
		return log.New(io.Discard, prefix, 0)
	}
}