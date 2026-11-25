package util

import "sync"

type waitingRequest struct {
	id      uint32
	respond func([]byte)
}

// RequestBuffer pairs requests for data with responses, in first-in,
// first-out order on both sides.
type RequestBuffer struct {
	lock *sync.Mutex
	// Requests waiting for a response, oldest first.
	waiting []waitingRequest
	// Responses waiting for a request, oldest first.
	responses [][]byte
}

func MakeRequestBuffer() *RequestBuffer {
	buffer := RequestBuffer{
		lock:      &sync.Mutex{},
		waiting:   make([]waitingRequest, 0),
		responses: make([][]byte, 0),
	}
	return &buffer
}

func (buffer *RequestBuffer) Request(id uint32, request func(response []byte)) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if len(buffer.responses) > 0 {
		response := buffer.responses[0]
		buffer.responses = buffer.responses[1:]
		request(response)
		return true
	} else {
		buffer.waiting = append(buffer.waiting, waitingRequest{id: id, respond: request})
		return false
	}
}

func (buffer *RequestBuffer) CancelRequest(id uint32) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	for i, request := range buffer.waiting {
		if request.id == id {
			buffer.waiting = append(buffer.waiting[:i], buffer.waiting[i+1:]...)
			return true
		}
	}
	return false
}

func (buffer *RequestBuffer) Respond(data []byte) {
	buffer.lock.Lock()
	if len(buffer.waiting) > 0 {
		// Answer the oldest waiting request
		request := buffer.waiting[0]
		buffer.waiting = buffer.waiting[1:]
		buffer.lock.Unlock()
		request.respond(data)
	} else {
		buffer.responses = append(buffer.responses, data)
		buffer.lock.Unlock()
	}
}
