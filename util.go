package main

import (
	"encoding/binary"
	"io"
)

func pad[T any](src []T, size int) []T {
	destination := make([]T, size)
	copy(destination, src)
	return destination
}

func readBE[T uint8 | uint16 | uint32](reader io.Reader) (T, error) {
	var val T
	err := binary.Read(reader, binary.BigEndian, &val)
	return val, err
}

func writeBE[T uint8 | uint16 | uint32](writer io.Writer, val T) error {
	return binary.Write(writer, binary.BigEndian, val)
}
