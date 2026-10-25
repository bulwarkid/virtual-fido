//go:build linux

package uhid

import "encoding/binary"

func buildCreateEvent(name string, rd []byte) []byte {
	buf := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(buf[:4], uhidEventCreate2)
	copy(buf[4:4+uhidNameLen], []byte(name))
	offset := 4 + uhidNameLen + uhidPhysLen + uhidUniqLen
	binary.LittleEndian.PutUint16(buf[offset:], uint16(len(rd))) // rd_size
	offset += 2
	binary.LittleEndian.PutUint16(buf[offset:], uhidBusUSB) // bus USB
	offset += 2
	binary.LittleEndian.PutUint32(buf[offset:], uhidVendorID) // vendor
	offset += 4
	binary.LittleEndian.PutUint32(buf[offset:], uhidProduct) // product
	offset += 4
	offset += 4 // version
	offset += 4 // country
	copy(buf[offset:], rd)
	return buf
}

func buildInputEvent(report []byte) []byte {
	buf := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(buf[:4], uhidEventInput2)
	binary.LittleEndian.PutUint16(buf[4:], uint16(len(report)))
	copy(buf[4+2:], report)
	return buf
}

func buildDestroyEvent() []byte {
	buf := make([]byte, uhidEventSize)
	binary.LittleEndian.PutUint32(buf[:4], uhidEventDestroy)
	return buf
}
