package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/fxamacker/cbor/v2"
)

func Panic(message string) {
	panic(fmt.Sprintf("%s\n%s", message, string(debug.Stack())))
}

func Assert(val bool, message string) {
	if !val {
		Panic(message)
	}
}

func CheckErr(err error, message string) {
	if err != nil {
		Panic(fmt.Sprintf("ERROR: %v - %v", message, err))
	}
}

func Try(try func(), catch func(val interface{})) {
	defer func() {
		if r := recover(); r != nil {
			catch(r)
		}
	}()
	try()
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

func FromBE[T any](valBytes []byte) T {
	buffer := bytes.NewBuffer(valBytes)
	val := ReadBE[T](buffer)
	return val
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

func Concat[T any](arrays ...[]T) []T {
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
	encOptions := cbor.CTAP2EncOptions()
	encMode, err := encOptions.EncMode()
	CheckErr(err, "Could not get encoding mode")
	data, err := encMode.Marshal(val)
	CheckErr(err, "Could not marshal CBOR")
	return data
}

func CStringToString(data []byte) string {
	// Converts a null-terminated series of bytes into a Go string
	i := strings.Index(string(data), "\x00")
	if i < 0 {
		// We want to aggressively panic here because it is almost certainly an error
		panic("No null termination in CString")
	}
	return string(data[:i])
}

func TimeoutSwitch(duration int) chan bool {
	timeoutSwitch := make(chan bool)
	go func() {
		time.Sleep(time.Millisecond * time.Duration(duration))
		timeoutSwitch <- false
	}()
	return timeoutSwitch
}

func SetTimeout(duration int, f func()) {
	go func() {
		time.Sleep(time.Millisecond * time.Duration(duration))
		f()
	}()
}
