//
//  USBDriver.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 12/30/22.
//

#include <os/log.h>

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOUserClient.h>
#include <DriverKit/IOLib.h>

#include "USBDriver.h"
#include "util.h"

#define Log(fmt, ...) GlobalLog("USBDriver - " fmt, ##__VA_ARGS__)

kern_return_t IMPL(USBDriver, Start) {
    Log("Start()");
    kern_return_t ret = kIOReturnSuccess;
    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        Log("Failed to start USBDriver: 0x%08x", ret);
        return ret;
    }
    ret = RegisterService();
    if (ret != kIOReturnSuccess) {
        Log("Failed to register service: 0x%08x", ret);
        return ret;
    }
    return kIOReturnSuccess;
}

kern_return_t IMPL(USBDriver, NewUserClient) {
    Log("NewUserClient()");
    kern_return_t ret = kIOReturnSuccess;
    IOService *service;
    ret = Create(this, "UserClientProperties", &service);
    if (ret != kIOReturnSuccess) {
        Log("Failed to create user client: 0x%08x", ret);
        return ret;
    }
    *userClient = OSDynamicCast(IOUserClient, service);
    if (!*userClient) {
        Log("Failed to cast UserClient");
        service->release();
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}
