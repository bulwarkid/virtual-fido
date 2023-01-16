//
//  USBUserClient.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 12/31/22.
//

#include <stdio.h>
#include <DriverKit/IOLib.h>
#include <DriverKit/OSData.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>

#include "util.h"
#include "USBDevice.h"
#include "USBDriverLib.h"
#include "USBUserClient.h"

#define Log(fmt, ...) GlobalLog("USBUserClient - " fmt, ##__VA_ARGS__)

const uint32_t MAX_SAVED_FRAMES = 16;


const IOUserClientMethodDispatch USBDriverMethodChecks[NumberOfUSBDriverMethods] = {
    [USBDriverMethodType_SendFrame] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleSendFrame,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
        .checkStructureInputSize = sizeof(usb_driver_hid_frame),
        .checkStructureOutputSize = 0,
    },
    [USBDriverMethodType_NotifyFrame] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleNotifyFrame,
        .checkCompletionExists = true,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
        .checkStructureInputSize = 0,
        .checkStructureOutputSize = 0,
    },
    [USBDriverMethodType_GetFrame] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleGetFrame,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
        .checkStructureInputSize = 0,
        .checkStructureOutputSize = sizeof(usb_driver_hid_frame),
    },
    [USBDriverMethodType_StartDevice] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleStartDevice,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
    },
    [USBDriverMethodType_StopDevice] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleStopDevice,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
    }
};

struct USBUserClient_IVars {
    USBDevice *_device = nullptr;
    OSAction* notifyFrameAction = nullptr;
    usb_driver_hid_frame saved_frame;
};

bool USBUserClient::init(void) {
    Log("init()");
    bool result = super::init();
    if (!result) {
        return false;
    }
    ivars = IONewZero(USBUserClient_IVars, 1);
    if (ivars == nullptr) {
        return false;
    }
    ivars->saved_frame.length = 0;
    return true;
}

void USBUserClient::free(void) {
    Log("free()");
    IOSafeDeleteNULL(ivars, USBUserClient_IVars, 1);
    super::free();
}

kern_return_t IMPL(USBUserClient, Stop) {
    Log("Stop()");
    clearDeviceIfNecessary();
    kern_return_t ret = Stop(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        Log("Failed to stop: 0x%08x", ret);
        return ret;
    }
    return kIOReturnSuccess;
}

void USBUserClient::clearDeviceIfNecessary() {
    if (ivars->_device) {
        ivars->_device->Terminate(0);
        ivars->_device->release();
        ivars->_device = nullptr;
    }
}

kern_return_t USBUserClient::ExternalMethod(uint64_t selector, IOUserClientMethodArguments *arguments, const IOUserClientMethodDispatch *dispatch, OSObject *target, void *reference) {
    Log("USBDriverMethod(%llu)", selector);
    if (selector >= 0) {
        if (selector < NumberOfUSBDriverMethods) {
            dispatch = &USBDriverMethodChecks[selector];
            if (!target) {
                target = this;
            }
        }
        return super::ExternalMethod(selector, arguments, dispatch, target, reference);
    }
    return kIOReturnBadArgument;
}

kern_return_t USBUserClient::StaticHandleStartDevice(USBUserClient* target, void* reference, IOUserClientMethodArguments* arguments) {
    return target->HandleStartDevice(reference, arguments);
}

kern_return_t USBUserClient::HandleStartDevice(void* reference, IOUserClientMethodArguments* arguments) {
    Log("StartDevice()");
    ivars->_device = USBDevice::newDevice(this);
    if (!ivars->_device) {
        Log("No device created");
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

kern_return_t USBUserClient::StaticHandleStopDevice(USBUserClient* target, void* reference, IOUserClientMethodArguments* arguments) {
    return target->HandleSendFrame(reference, arguments);
}

kern_return_t USBUserClient::HandleStopDevice(void* reference, IOUserClientMethodArguments* arguments) {
    clearDeviceIfNecessary();
    return kIOReturnSuccess;
}

kern_return_t USBUserClient::StaticHandleSendFrame(USBUserClient* target, void* reference, IOUserClientMethodArguments* arguments) {
    return target->HandleSendFrame(reference, arguments);
}

kern_return_t USBUserClient::HandleSendFrame(void* reference, IOUserClientMethodArguments* arguments) {
    usb_driver_hid_frame *frame = (usb_driver_hid_frame*) arguments->structureInput->getBytesNoCopy();
    if (frame->length <= 0 || frame->length >= sizeof(frame->data)/sizeof(frame->data[0])) {
        return kIOReturnBadArgument;
    }
    if (ivars->_device) {
        IOBufferMemoryDescriptor *report = createMemoryDescriptorWithBytes((void*)frame->data, sizeof(uint64_t) * frame->length);
        ivars->_device->sendReportFromDevice(report);
        report->release();
    }
    return kIOReturnSuccess;
}

kern_return_t USBUserClient::StaticHandleNotifyFrame(USBUserClient* target, void* reference, IOUserClientMethodArguments* arguments) {
    return target->HandleNotifyFrame(reference, arguments);
}

kern_return_t USBUserClient::HandleNotifyFrame(void* reference, IOUserClientMethodArguments* arguments) {
    if (arguments->completion == nullptr) {
        Log("Invalid NotifiyFrame completion");
        return kIOReturnBadArgument;
    }
    ivars->notifyFrameAction = arguments->completion;
    ivars->notifyFrameAction->retain();
    return kIOReturnSuccess;
}

void USBUserClient::newHIDFrame(IOMemoryDescriptor *report, IOHIDReportType reportType) {
    Log("newHIDFrame()");

    if (ivars->notifyFrameAction == nullptr) {
        Log("No notify frame action specified");
        return;
    }
    
    if (ivars->saved_frame.length != 0) {
        Log("Non-zero length of saved frame: %llu", ivars->saved_frame.length);
        return;
    }
    
    uint64_t address;
    uint64_t length;
    report->Map(0, 0, 0, 0, &address, &length);
    uint64_t *byteAddress = reinterpret_cast<uint64_t*>(address);
    ivars->saved_frame.length = length;
    bzero(ivars->saved_frame.data, sizeof(ivars->saved_frame.data));
    memcpy(ivars->saved_frame.data, byteAddress, length);
    Log("Received frame of length %llu", length);
    
    AsyncCompletion(ivars->notifyFrameAction, kIOReturnSuccess, nullptr, 0);
}

kern_return_t USBUserClient::StaticHandleGetFrame(USBUserClient* target, void* reference, IOUserClientMethodArguments* arguments) {
    return target->HandleGetFrame(reference, arguments);
}

kern_return_t USBUserClient::HandleGetFrame(void* reference, IOUserClientMethodArguments* arguments) {
    Log("GetFrame()");
    if (ivars->saved_frame.length == 0) {
        Log("No frame found to return");
        return kIOReturnNoFrames;
    }
    Log("Returning frame with length %llu", ivars->saved_frame.length);
    arguments->structureOutput = OSData::withBytes(&ivars->saved_frame, sizeof(usb_driver_hid_frame));
    ivars->saved_frame.length = 0;
    bzero(ivars->saved_frame.data, sizeof(ivars->saved_frame.data));
    return kIOReturnSuccess;
}


