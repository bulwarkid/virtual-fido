package main

import "virtual_fido"

func main() {
	device := virtual_fido.VirtualFIDO{}
	device.Start()
}
