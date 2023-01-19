//
//  util.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 1/13/23.
//

#include <stdio.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>

#include "util.h"

IOBufferMemoryDescriptor *createMemoryDescriptorWithBytes(const void *bytes, uint64_t length) {
    IOBufferMemoryDescriptor *buffer;
    IOBufferMemoryDescriptor::Create(kIOMemoryDirectionInOut, length, 0, &buffer);
    buffer->SetLength(length);
    IOAddressSegment range;
    buffer->GetAddressRange(&range);
    memcpy((void*)range.address, bytes, length);
    return buffer;
}
