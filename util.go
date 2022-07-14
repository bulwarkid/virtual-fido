package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

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

func writeBE[T any](writer io.Writer, val T) {
	beBytes := toBE(val)
	write(writer, beBytes)
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
	fmt.Printf("\tWRITE: [%d]byte{%v}\n", len(data), data)
	_, err := writer.Write(data)
	checkErr(err, "Could not write data")
}
