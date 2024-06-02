package util

import "sync"

type RequestBuffer struct {
	lock           *sync.Mutex
	waitingForData map[uint32]func([]byte)
	responses      [][]byte
}

func MakeRequestBuffer() *RequestBuffer {
	buffer := RequestBuffer{
		lock:           &sync.Mutex{},
		waitingForData: make(map[uint32]func([]byte)),
		responses:      make([][]byte, 0),
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
		buffer.waitingForData[id] = request
		return false
	}
}

func (buffer *RequestBuffer) CancelRequest(id uint32) bool {
	buffer.lock.Lock()
	defer buffer.lock.Unlock()
	if _, ok := buffer.waitingForData[id]; ok {
		delete(buffer.waitingForData, id)
		return true
	} else {
		return false
	}
}

func (buffer *RequestBuffer) Respond(data []byte) {
	buffer.lock.Lock()
	if len(buffer.waitingForData) > 0 {
		// Get first waiting request
		var id uint32
		var request func([]byte)
		for id, request = range buffer.waitingForData {
			break
		}
		delete(buffer.waitingForData, id)
		buffer.lock.Unlock()
		request(data)
	} else {
		buffer.responses = append(buffer.responses, data)
		buffer.lock.Unlock()
	}
}
