package main

func main() {
	device := FIDODevice{}
	server := NewUSBIPServer(&device)
	server.start()
}
