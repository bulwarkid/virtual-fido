package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"
	"unicode/utf16"

	"github.com/fxamacker/cbor/v2"
)

func Assert(val bool, message string) {
	if !val {
		panic(message)
	}
}

func CheckErr(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf("ERROR: %v - %v", message, err))
	}
}

func CheckEOF(conn *net.Conn) {
	_, err := (*conn).Read([]byte{})
	if err != nil {
		fmt.Println("Getting err from connection:", err)
	}
}

func Pad[T any](src []T, size int) []T {
	destination := make([]T, size)
	copy(destination, src)
	return destination
}

func ReadBE[T any](reader io.Reader) T {
	var value T
	err := binary.Read(reader, binary.BigEndian, &value)
	CheckErr(err, "Could not read data")
	return value
}

func ReadLE[T any](reader io.Reader) T {
	var value T
	err := binary.Read(reader, binary.LittleEndian, &value)
	CheckErr(err, "Could not read data")
	return value
}

func ToLE[T any](val T) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, val)
	return buffer.Bytes()
}

func ToBE[T any](val T) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, val)
	return buffer.Bytes()
}

func Write(writer io.Writer, data []byte) {
	//fmt.Printf("\tWRITE: [%d]byte{%v}\n", len(data), data)
	_, err := writer.Write(data)
	CheckErr(err, "Could not write data")
}

func Read(reader io.Reader, length uint) []byte {
	output := make([]byte, length)
	_, err := reader.Read(output)
	CheckErr(err, "Could not read data")
	return output
}

func Fill(buffer *bytes.Buffer, length int) {
	if buffer.Len() < length {
		zeroes := make([]byte, length-buffer.Len())
		Write(buffer, zeroes)
	}
}

func Utf16encode(message string) []byte {
	buffer := new(bytes.Buffer)
	for _, val := range utf16.Encode([]rune(message)) {
		binary.Write(buffer, binary.LittleEndian, val)
	}
	return buffer.Bytes()
}

func SizeOf[T any]() uint8 {
	var val T
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, &val)
	return uint8(buffer.Len())
}

func Flatten[T any](arrays [][]T) []T {
	output := make([]T, 0)
	for _, arr := range arrays {
		output = append(output, arr...)
	}
	return output
}

func StartRecurringFunction(f func(), interval int64) chan interface{} {
	stopSignal := make(chan interface{}, 1)
	trigger := make(chan interface{}, 1)
	wait := func() {
		time.Sleep(time.Millisecond * time.Duration(interval))
		trigger <- nil
	}
	go func() {
		for {
			go wait()
			select {
			case <-trigger:
				f()
			case <-stopSignal:
				return
			}
		}
	}()
	return stopSignal
}

func Delay(f func(), interval int64) {
	go func() {
		time.Sleep(time.Millisecond * time.Duration(interval))
		f()
	}()
}


func BytesToBigInt(b []byte) *big.Int {
	return big.NewInt(0).SetBytes(b)
}

func MarshalCBOR(val interface{}) []byte {
	data, err := cbor.Marshal(val)
	CheckErr(err, "Could not marshal CBOR")
	return data
}


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

func NewLogger(prefix string, enabled bool) *log.Logger {
	if enabled {
		return log.New(logOutput, prefix, 0)
	} else {
		return log.New(io.Discard, prefix, 0)
	}
}
