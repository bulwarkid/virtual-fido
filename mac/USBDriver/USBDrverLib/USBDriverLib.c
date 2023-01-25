//
//  USBDriverLib.c
//  USBDriverLib
//
//  Created by Chris de la Iglesia on 1/13/23.
//

#include <stdlib.h>
#include <IOKit/usb/USB.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDShared.h>

#include "USBDriverLib.h"

#define DEBUG 1

static const char* DEXT_IDENTIFIER = "USBDriver";
static const char* FULL_DEXT_IDENTIFIER = "id.bulwark.VirtualUSBDriver.driver";


static void debugf(const char* fmt, ...) {
    if (DEBUG) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}

static void print_return(kern_return_t ret) {
    debugf("Err system: 0x%x\n", err_get_system(ret));
    debugf("Err sub: 0x%x\n", err_get_sub(ret));
    debugf("Err code: 0x%x\n", err_get_code(ret));
}

static void notify_frame(void* refcon, IOReturn result, void** args, uint32_t numArgs) {
    kern_return_t ret = kIOReturnSuccess;
    usb_driver_device_t *device = (usb_driver_device_t *)refcon;
    
    usb_driver_hid_frame_t frame;
    size_t outputSize = sizeof(usb_driver_hid_frame_t);
    ret = IOConnectCallStructMethod(device->connection, USBDriverMethodType_GetFrame, NULL, 0, &frame, &outputSize);
    if (ret != kIOReturnSuccess) {
        debugf("Invalid return when getting frame: %d\n", ret);
        print_return(ret);
        return;
    }

    device->receiveData(device, &frame);
}

static kern_return_t register_callback(usb_driver_device_t *device) {
    kern_return_t ret = kIOReturnSuccess;
    
    IONotificationPortRef notificationPort = IONotificationPortCreate(kIOMainPortDefault);
    if (notificationPort == NULL) {
        debugf("Failed to create notification port\n");
        return kIOReturnError;
    }
    
    mach_port_t machNotificationPort = IONotificationPortGetMachPort(notificationPort);
    if (machNotificationPort == 0) {
        debugf("Failed to get mach notification port\n");
        return kIOReturnError;
    }
    
    CFRunLoopSourceRef runLoopSource = IONotificationPortGetRunLoopSource(notificationPort);
    if (runLoopSource == NULL) {
        debugf("Failed to get run loop\n");
        return kIOReturnError;
    }
    
    CFRunLoopAddSource(device->globalRunLoop, runLoopSource, kCFRunLoopDefaultMode);
    
    io_async_ref64_t asyncRef = {};
    asyncRef[kIOAsyncCalloutFuncIndex] = (io_user_reference_t)notify_frame;
    asyncRef[kIOAsyncCalloutRefconIndex] = (io_user_reference_t)device;
    ret = IOConnectCallAsyncScalarMethod(device->connection, USBDriverMethodType_NotifyFrame, machNotificationPort, asyncRef, kIOAsyncCalloutCount, NULL, 0, NULL, 0);
    if (ret != kIOReturnSuccess) {
        debugf("Failed to register callback\n");
        return ret;
    }
    
    return kIOReturnSuccess;
}

static io_connect_t open_connection(void) {
    kern_return_t ret;
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceNameMatching(DEXT_IDENTIFIER));
    if (!service) {
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(FULL_DEXT_IDENTIFIER));
        if (!service) {
            debugf("Could not find matching service\n");
            return IO_OBJECT_NULL;
        }
    }
    
    io_connect_t connection;
    ret = IOServiceOpen(service, mach_task_self_, kIOHIDServerConnectType, &connection);
    if (ret != kIOReturnSuccess) {
        debugf("Could not open connection: 0x%x\n", ret);
        print_return(ret);
        return IO_OBJECT_NULL;
    }
    return connection;
}

usb_driver_device_t *usb_driver_init_device(usb_driver_receive_data_callback receiveData) {
    usb_driver_device_t *device = malloc(sizeof(usb_driver_device_t));
    device->receiveData = receiveData;
    return device;
}

void usb_driver_start(usb_driver_device_t *device) {
    kern_return_t ret = kIOReturnSuccess;
    device->globalRunLoop = CFRunLoopGetCurrent();
    CFRetain(device->globalRunLoop);
    
    device->connection = open_connection();
    if (device->connection == IO_OBJECT_NULL) {
        debugf("Could not open connection\n");
        return;
    }
    
    ret = register_callback(device);
    if (ret != kIOReturnSuccess) {
        return;
    }
    
    ret = IOConnectCallScalarMethod(device->connection, USBDriverMethodType_StartDevice, NULL, 0, NULL, 0);
    if (ret != kIOReturnSuccess) {
        debugf("IOConnectCallScalarMethod failed: 0x%08x\n", ret);
        print_return(ret);
        return;
    }
    
    CFRunLoopRun();
    
    ret = IOServiceClose(device->connection);
    if (ret != kIOReturnSuccess) {
        debugf("Failed to close connection: 0x%08x\n", ret);
        print_return(ret);
        return;
    }
    
    CFRelease(device->globalRunLoop);
}

void usb_driver_stop(usb_driver_device_t *device) {
    CFRunLoopStop(device->globalRunLoop);
}

void usb_driver_send_frame(usb_driver_device_t *device, usb_driver_hid_frame_t *frame) {
    kern_return_t ret = kIOReturnSuccess;
    
    size_t inputSize = sizeof(usb_driver_hid_frame_t);
    ret = IOConnectCallStructMethod(device->connection, USBDriverMethodType_SendFrame, frame, inputSize, NULL, 0);
    if (ret != kIOReturnSuccess) {
        debugf("Could not send frame: 0x%x\n", ret);
        print_return(ret);
        return;
    }
}
