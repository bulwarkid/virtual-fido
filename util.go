package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"
)

func pad[T any](src []T, size int) []T {
	destination := make([]T, size)
	copy(destination, src)
	return destination
}

func readBE[T any](reader io.Reader) (T, error) {
	var value T
	fmt.Printf("%#v %d\n", value, unsafe.Sizeof(value))
	singleByte := make([]byte, 1)
	n, err := reader.Read(singleByte)
	fmt.Println("Single byte: ", n, err, singleByte)
	restOfBytes := make([]byte, unsafe.Sizeof(value)-1)
	n, err = reader.Read(restOfBytes)
	fmt.Println("Rest of bytes: ", n, err, restOfBytes)
	if err != nil {
		return value, err
	}
	buffer := new(bytes.Buffer)
	buffer.Write(singleByte)
	buffer.Write(restOfBytes)
	err = binary.Read(buffer, binary.BigEndian, &value)
	return value, err
}

func readLE[T any](reader io.Reader) (T, error) {
	value := new(T)
	fmt.Printf("%#v %d\n", value, unsafe.Sizeof(*value))
	rawBytes := make([]byte, unsafe.Sizeof(*value))
	n, err := reader.Read(rawBytes)
	fmt.Println("Raw read: ", n, err, rawBytes)
	if err != nil {
		return *value, err
	}
	err = binary.Read(bytes.NewBuffer(rawBytes), binary.LittleEndian, value)
	return *value, err
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
