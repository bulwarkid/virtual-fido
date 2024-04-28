package util

type RequestBuffer struct {
	waitingForData map[uint32]func([]byte)
	responses [][]byte
}

func MakeRequestBuffer() *RequestBuffer {
	buffer := RequestBuffer{
		waitingForData: make(map[uint32]func([]byte)),
		responses: make([][]byte, 0),
	}
	return &buffer
}

func (buffer *RequestBuffer) Request(id uint32, request func(response []byte)) bool {
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
	if _, ok := buffer.waitingForData[id]; ok {
		delete(buffer.waitingForData, id)
		return true
	} else {
		return false
	}
}

func (buffer *RequestBuffer) Respond(data []byte) {
	if len(buffer.waitingForData) > 0 {
		// Get first waiting request
		for id, request := range buffer.waitingForData {
			delete(buffer.waitingForData, id)
			request(data)
			return
		}
	} else {
		buffer.responses = append(buffer.responses, data)
	}
}