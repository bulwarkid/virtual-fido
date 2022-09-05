package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

var wait *sync.WaitGroup = nil

func run(args ...string) {
	fmt.Printf("Starting program %#v\n", args)
	prog := exec.Command(args[0], args[1:]...)
	fmt.Printf("%#v %#v\n", prog, args[1:])
	prog.Stdout = os.Stdout
	prog.Stderr = os.Stderr
	err := prog.Run()
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	wait.Done()
}

func main() {
	wait.Add(2)
	go run("go", "run", "demo/main.go")
	time.Sleep(time.Millisecond * 500)
	go run("./usbip/usbip.exe", "attach", "-r", "127.0.0.1", "-b", "2-2")
	wait.Wait()
}
