package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

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

func readBE[T any](reader io.Reader) (T, error) {
	var value T
	err := binary.Read(reader, binary.BigEndian, &value)
	return value, err
}

func readLE[T any](reader io.Reader) (T, error) {
	var value T
	err := binary.Read(reader, binary.LittleEndian, &value)
	return value, err
}

func writeBE[T any](writer io.Writer, val T) error {
	beBytes := toBE(val)
	return write(writer, beBytes)
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

func write(writer io.Writer, data []byte) error {
	fmt.Printf("WRITE: %v %d\n", data, len(data))
	_, err := writer.Write(data)
	return err
}
