package virtual_fido

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"
)

func assert(val bool, message string) {
	if !val {
		panic(message)
	}
}

func checkErr(err error, message string) {
	if err != nil {
		panic(fmt.Sprintf("ERROR: %v - %v", message, err))
	}
}

func checkEOF(conn *net.Conn) {
	_, err := (*conn).Read([]byte{})
	if err != nil {
		fmt.Println("Getting err from connection:", err)
	}
}

func pad[T any](src []T, size int) []T {
	destination := make([]T, size)
	copy(destination, src)
	return destination
}

func readBE[T any](reader io.Reader) T {
	var value T
	err := binary.Read(reader, binary.BigEndian, &value)
	checkErr(err, "Could not read data")
	return value
}

func readLE[T any](reader io.Reader) T {
	var value T
	err := binary.Read(reader, binary.LittleEndian, &value)
	checkErr(err, "Could not read data")
	return value
}

func toLE[T any](val T) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, val)
	return buffer.Bytes()
}

func toBE[T any](val T) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, val)
	return buffer.Bytes()
}

func write(writer io.Writer, data []byte) {
	//fmt.Printf("\tWRITE: [%d]byte{%v}\n", len(data), data)
	_, err := writer.Write(data)
	checkErr(err, "Could not write data")
}

func read(reader io.Reader, length uint) []byte {
	output := make([]byte, length)
	_, err := reader.Read(output)
	checkErr(err, "Could not read data")
	return output
}

func fill(buffer *bytes.Buffer, length int) {
	if buffer.Len() < length {
		zeroes := make([]byte, length-buffer.Len())
		write(buffer, zeroes)
	}
}

func utf16encode(message string) []byte {
	buffer := new(bytes.Buffer)
	for _, val := range utf16.Encode([]rune(message)) {
		binary.Write(buffer, binary.LittleEndian, val)
	}
	return buffer.Bytes()
}

func sizeOf[T any]() uint8 {
	var val T
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, &val)
	return uint8(buffer.Len())
}

func flatten[T any](arrays [][]T) []T {
	output := make([]T, 0)
	for _, arr := range arrays {
		output = append(output, arr...)
	}
	return output
}

func startRecurringFunction(f func(), interval int64) chan interface{} {
	stopSignal := make(chan interface{})
	trigger := make(chan interface{})
	wait := func() {
		time.Sleep(time.Millisecond * time.Duration(interval))
		trigger <- 0
	}
	go func() {
		go wait()
		switch {
		case <-trigger:
			f()
			go wait()
		case <-stopSignal:
			return
		}
	}()
	return stopSignal
}
