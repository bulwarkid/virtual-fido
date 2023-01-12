//
//  USBUserClient.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 12/31/22.
//

#include <stdio.h>
#include <DriverKit/IOLib.h>

#include "util.h"
#include "USBDevice.h"
#include "USBUserClient.h"

#define Log(fmt, ...) GlobalLog("USBUserClient - " fmt, ##__VA_ARGS__)

typedef enum {
    ExternalMethodType_SendFrame = 0,
    ExternalMethodType_NotifyFrame = 1,
    ExternalMethodType_StartDevice = 2,
    ExternalMethodType_StopDevice = 3,
    NumberOfExternalMethods
} ExternalMethodType;

const IOUserClientMethodDispatch externalMethodChecks[NumberOfExternalMethods] = {
    [ExternalMethodType_SendFrame] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleSendFrame,
        .checkCompletionExists = false,
        // TODO: Add more checks for arguments once finalized
    },
    [ExternalMethodType_NotifyFrame] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleNotifyFrame,
        .checkCompletionExists = true,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
        .checkStructureInputSize = 0,
        .checkStructureOutputSize = 0,
    },
    [ExternalMethodType_StartDevice] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleStartDevice,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
    },
    [ExternalMethodType_StopDevice] = {
        .function = (IOUserClientMethodFunction)USBUserClient::StaticHandleStopDevice,
        .checkCompletionExists = false,
        .checkScalarInputCount = 0,
        .checkScalarOutputCount = 0,
    }
};

struct USBUserClient_IVars {
    USBDevice *_device;
    OSAction* notifyFrameAction = nullptr;
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
    Log("ExternalMethod(%llu)", selector);
    if (selector >= 0) {
        if (selector < NumberOfExternalMethods) {
            dispatch = &externalMethodChecks[selector];
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
    // TODO: Implement
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
