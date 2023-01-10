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

struct USBUserClient_IVars {
    USBDevice *_device;
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
    kern_return_t ret = Stop(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        Log("Failed to stop: 0x%08x", ret);
        return ret;
    }
    return kIOReturnSuccess;
}

kern_return_t USBUserClient::ExternalMethod(uint64_t selector, IOUserClientMethodArguments *arguments, const IOUserClientMethodDispatch *dispatch, OSObject *target, void *reference) {
    Log("ExternalMethod()");
    ivars->_device = USBDevice::newDevice(this);
    if (!ivars->_device) {
        Log("No device created");
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}
