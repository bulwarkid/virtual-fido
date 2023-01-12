//
//  main.cpp
//  USBDriverTester
//
//  Created by Chris de la Iglesia on 1/9/23.
//

#include <iostream>
#include <IOKit/usb/USB.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDShared.h>

static const char* dextIdentifier = "USBDriver";
static const char* fullDextIdentifier = "id.bulwark.USBDriver.driver";

static void NotifyFrameCallback(void* refcon, IOReturn result, void** args, uint32_t numArgs) {
    printf("NotifyFrame callback called\n");
}

CFRunLoopRef globalRunLoop = nullptr;

kern_return_t registerAsyncCallback(io_connect_t connection) {
    kern_return_t ret = kIOReturnSuccess;
    
    
    IONotificationPortRef notificationPort = IONotificationPortCreate(kIOMainPortDefault);
    if (notificationPort == nullptr) {
        printf("Failed to create notification port\n");
        return kIOReturnError;
    }
    
    mach_port_t machNotificationPort = IONotificationPortGetMachPort(notificationPort);
    if (machNotificationPort == 0) {
        printf("Failed to get mach notification port\n");
        return kIOReturnError;
    }
    
    CFRunLoopSourceRef runLoopSource = IONotificationPortGetRunLoopSource(notificationPort);
    if (runLoopSource == nullptr) {
        printf("Failed to get run loop\n");
        return kIOReturnError;
    }
    
    CFRunLoopAddSource(globalRunLoop, runLoopSource, kCFRunLoopDefaultMode);
    
    io_async_ref64_t asyncRef = {};
    asyncRef[kIOAsyncCalloutFuncIndex] = (io_user_reference_t)NotifyFrameCallback;
    asyncRef[kIOAsyncCalloutRefconIndex] = (io_user_reference_t)nullptr;
    ret = IOConnectCallAsyncScalarMethod(connection, 1, machNotificationPort, asyncRef, kIOAsyncCalloutCount, nullptr, 0, nullptr, 0);
    if (ret != kIOReturnSuccess) {
        printf("Failed to register callback\n");
        return ret;
    }
    
    return kIOReturnSuccess;
}

int main() {
    printf("Looking for %s...\n", dextIdentifier);
    kern_return_t ret = kIOReturnSuccess;
    
    globalRunLoop = CFRunLoopGetCurrent();
    CFRetain(globalRunLoop);
    
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceNameMatching(dextIdentifier));
    if (!service) {
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(fullDextIdentifier));
        if (!service) {
            printf("Could not find matching service\n");
            return 1;
        }
    }
    io_connect_t connection = IO_OBJECT_NULL;
    ret = IOServiceOpen(service, mach_task_self_, kIOHIDServerConnectType, &connection);
    if (ret != kIOReturnSuccess) {
        printf("Could not open connection: 0x%08x\n", ret);
        return 1;
    }
    
    ret = registerAsyncCallback(connection);
    if (ret != kIOReturnSuccess) {
        return 1;
    }
    
    // TODO: Actually share selector value in code
    uint32_t startDeviceSelector = 2;
    ret = IOConnectCallScalarMethod(connection, startDeviceSelector, nullptr, 0, nullptr, 0);
    if (ret != kIOReturnSuccess) {
        printf("IOConnectCallScalarMethod failed: 0x%08x\n", ret);
        return 1;
    }
    
    CFRunLoopRun();
    
    ret = IOServiceClose(connection);
    if (ret != kIOReturnSuccess) {
        printf("Failed to close connection: 0x%08x\n", ret);
        return 1;
    }
    
    CFRelease(globalRunLoop);
    
    return 0;
}
