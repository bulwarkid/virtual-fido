package util

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
)

func TestRequestBuffer(t *testing.T) {
	buffer := MakeRequestBuffer()
	makeRequest := func(val []byte) func([]byte) {
		return func(response []byte) {
			test.AssertEqual(t, response[0], val[0], "Request does not equal response")
		}
	}
	buffer.Request(1, makeRequest([]byte{1}))
	buffer.Request(2, makeRequest([]byte{2}))
	buffer.Request(3, makeRequest([]byte{3}))
	go func() {
		buffer.Respond([]byte{1})
		buffer.Respond([]byte{2})
		buffer.Respond([]byte{3})
		buffer.Respond([]byte{4})
		buffer.Respond([]byte{5})
		buffer.Respond([]byte{6})
	}()
	buffer.Request(3, makeRequest([]byte{4}))
	buffer.Request(3, makeRequest([]byte{5}))
	buffer.Request(3, makeRequest([]byte{6}))
}