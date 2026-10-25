package util

import "sync"

type RequestBuffer struct {
	lock           *sync.Mutex
	waitingForData map[uint32][]func([]byte)
	waitingQueue   []uint32
	responses      [][]byte
}

func MakeRequestBuffer() *RequestBuffer {
	buffer := RequestBuffer{
		lock:           &sync.Mutex{},
		waitingForData: make(map[uint32][]func([]byte)),
		waitingQueue:   make([]uint32, 0),
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
		buffer.waitingForData[id] = append(buffer.waitingForData[id], request)
		buffer.waitingQueue = append(buffer.waitingQueue, id)
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
	for len(buffer.waitingQueue) > 0 {
		id := buffer.waitingQueue[0]
		buffer.waitingQueue = buffer.waitingQueue[1:]
		if requests, ok := buffer.waitingForData[id]; ok && len(requests) > 0 {
			request := requests[0]
			if len(requests) == 1 {
				delete(buffer.waitingForData, id)
			} else {
				buffer.waitingForData[id] = requests[1:]
			}
			buffer.lock.Unlock()
			request(data)
			return
		}
	}
	buffer.responses = append(buffer.responses, data)
	buffer.lock.Unlock()
}
