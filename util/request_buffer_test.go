package util

import (
	"sync"
	"testing"

	"github.com/bulwarkid/virtual-fido/test"
)

func TestRequestBufferAnswersWaitingRequestsInOrder(t *testing.T) {
	buffer := MakeRequestBuffer()
	received := make([]byte, 0)
	record := func(response []byte) { received = append(received, response[0]) }

	for id := uint32(1); id <= 5; id++ {
		test.Assert(t, !buffer.Request(id, record), "request answered without a response")
	}
	for value := byte(1); value <= 5; value++ {
		buffer.Respond([]byte{value})
	}
	test.AssertArrEqual(t, received, []byte{1, 2, 3, 4, 5}, "responses not delivered in request order")
}

func TestRequestBufferQueuesResponsesInOrder(t *testing.T) {
	buffer := MakeRequestBuffer()
	buffer.Respond([]byte{1})
	buffer.Respond([]byte{2})

	received := make([]byte, 0)
	record := func(response []byte) { received = append(received, response[0]) }
	test.Assert(t, buffer.Request(1, record), "queued response not delivered")
	test.Assert(t, buffer.Request(2, record), "queued response not delivered")
	test.Assert(t, !buffer.Request(3, record), "request answered without a response")
	test.AssertArrEqual(t, received, []byte{1, 2}, "queued responses not delivered in order")
}

func TestRequestBufferCancelRequest(t *testing.T) {
	buffer := MakeRequestBuffer()
	var first, second []byte
	buffer.Request(1, func(response []byte) { first = response })
	buffer.Request(2, func(response []byte) { second = response })

	test.Assert(t, buffer.CancelRequest(1), "waiting request not cancelled")
	test.Assert(t, !buffer.CancelRequest(1), "request cancelled twice")
	buffer.Respond([]byte{7})
	test.Assert(t, first == nil, "cancelled request received a response")
	test.AssertArrEqual(t, second, []byte{7}, "response not delivered to the remaining request")
}

func TestRequestBufferConcurrent(t *testing.T) {
	const count = 1000
	buffer := MakeRequestBuffer()
	results := make([]byte, count)
	var done sync.WaitGroup
	done.Add(count)

	go func() {
		for i := 0; i < count; i++ {
			buffer.Respond([]byte{byte(i)})
		}
	}()
	for i := 0; i < count; i++ {
		index := i
		buffer.Request(uint32(i), func(response []byte) {
			results[index] = response[0]
			done.Done()
		})
	}
	done.Wait()
	for i := 0; i < count; i++ {
		if results[i] != byte(i) {
			t.Fatalf("request %d received response %d", i, results[i])
		}
	}
}
