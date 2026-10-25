import os

def write_client_c():
    content = """
#include "output/include/USBDriverLib/USBDriverLib.h"
#include "_cgo_export.h"
#include <unistd.h>
#include <string.h>

static usb_driver_device_t *device;

void receive_data(usb_driver_device_t *device, usb_driver_hid_frame_t *frame) {
    receiveDataCallback(frame->data, frame->length);
}

void send_data(void *data, int length) {
    if (length > 64) {
        length = 64;
    }

    // Add small delay to prevent overflowing the OS HID queue
    usleep(5000);

    usb_driver_hid_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    memcpy(frame.data, data, length);
    frame.length = length;
    usb_driver_send_frame(device, &frame);
}

void start_device(void) {
    device = usb_driver_init_device(receive_data);
    usb_driver_start(device);
}"""
    with open("mac/client.c", "w") as f:
        f.write(content)

def write_usb_device_cpp():
    # USBDevice.cpp had an extra empty line at the end in uhid
    # We add our Start() and RegisterService() calls
    content = """//
//  USBDevice.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 12/31/22.
//

#include <stdio.h>
#include <DriverKit/OSString.h>
#include <DriverKit/OSNumber.h>
#include <DriverKit/OSDictionary.h>
#include <DriverKit/OSBoolean.h>
#include <DriverKit/OSData.h>
#include <DriverKit/IOLib.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>
#include <HIDDriverKit/IOHIDUsageTables.h>
#include <HIDDriverKit/IOHIDDeviceKeys.h>

#include "util.h"
#include "USBUserClient.h"
#include "USBDevice.h"

#define Log(fmt, ...) GlobalLog("USBDevice - " fmt, ##__VA_ARGS__)

#define CTAPHID_FRAME_SIZE 64

constexpr unsigned char fidoReportDescriptor[] = {6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2, 9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192};

USBDevice* USBDevice::newDevice(IOService *provider) {
    Log("newDevice()");
    IOService *service;
    kern_return_t ret = provider->Create(provider, "DeviceProperties", &service);
    if (ret != kIOReturnSuccess) {
        Log("Failed to create device using provider: 0x%08x", ret);
        return nullptr;
    }
    USBDevice *device = OSRequiredCast(USBDevice, service);
    if (!device) {
        Log("Failed to cast provided device to USBDevice");
        return nullptr;
    }

    ret = device->Start(provider);
    if (ret != kIOReturnSuccess) {
        Log("Failed to start device: 0x%08x", ret);
        device->release();
        return nullptr;
    }

    ret = device->RegisterService();
    if (ret != kIOReturnSuccess) {
        Log("Failed to register device: 0x%08x", ret);
        device->Terminate(0);
        device->release();
        return nullptr;
    }

    return device;
}

OSData* USBDevice::newReportDescriptor(void) {
    Log("newReportDescriptor()");
    return OSData::withBytes(fidoReportDescriptor, sizeof(fidoReportDescriptor));
}

OSDictionary* USBDevice::newDeviceDescription(void) {
    Log("newDeviceDescription()");
    struct KV {
        char const *key;
        OSObject *value;
    } kvs[] = {
        {
            kIOHIDTransportKey,
            OSString::withCString("Virtual")
        },
        {
            kIOHIDManufacturerKey,
            OSString::withCString("VirtualFIDO")
        },
        {
            kIOHIDVersionNumberKey,
            OSNumber::withNumber(1, 8 * sizeof(1))
        },
        {
            kIOHIDProductKey,
            OSString::withCString("VirtualFIDO")
        },
        {
            kIOHIDSerialNumberKey,
            OSString::withCString("123")
        },
        
        {
            kIOHIDVendorIDKey,
            OSNumber::withNumber(123, 32)
        },
        {
            kIOHIDProductIDKey,
            OSNumber::withNumber(123, 32)
        },
        {
            kIOHIDLocationIDKey,
            OSNumber::withNumber(123, 32)
        },
        {
            kIOHIDCountryCodeKey,
            OSNumber::withNumber(840, 32)
        },
        {
            kIOHIDPrimaryUsagePageKey,
            OSNumber::withNumber(kHIDPage_FIDO, 32)
        },
        {
            kIOHIDPrimaryUsageKey,
            OSNumber::withNumber(kHIDUsage_FIDO_U2FDevice, 32)
        },
        {
            "RegisterService",
            kOSBooleanTrue
        },
        {
            "HIDDefaultBehavior",
            kOSBooleanTrue
        },
        {
            "AppleVendorSupported",
            kOSBooleanTrue
        }
    };
    auto numKVs = sizeof(kvs) / sizeof(KV);
    
    auto description = OSDictionary::withCapacity(static_cast<uint32_t>(numKVs));
    for (int i = 0; i < numKVs; i++) {
        auto [key, value] = kvs[i];
        description->setObject(key, value);
        value->release();
    }
    
    return description;
}

kern_return_t USBDevice::getReport(IOMemoryDescriptor *report, IOHIDReportType reportType, IOOptionBits options, uint32_t completionTimeout, OSAction *action) {
    Log("getReport(%d)", reportType);
    return kIOReturnSuccess;
}

kern_return_t USBDevice::setReport(IOMemoryDescriptor *report, IOHIDReportType reportType, IOOptionBits options, uint32_t completionTimeout, OSAction *action) {
    Log("setReport(reportType: %d, completionTimeout: %u)", reportType, completionTimeout);
    USBUserClient *userClient = OSDynamicCast(USBUserClient, GetProvider());
    if (userClient) {
        userClient->newHIDFrame(report, reportType);
    } else {
        Log("No user client found");
        return kIOReturnError;
    }
    super::CompleteReport(action, kIOReturnSuccess, CTAPHID_FRAME_SIZE);
    return kIOReturnSuccess;
}

void printReport(IOMemoryDescriptor *report) {
    uint64_t address;
    uint64_t length;
    report->Map(0, 0, 0, 0, &address, &length);
    uint64_t *addressPointer = (uint64_t*)address;
    for(int i = 0; i < 8; i++) {
        Log("Report Data: %llx", addressPointer[i]);
    }
}

void USBDevice::sendReportFromDevice(IOMemoryDescriptor *report) {
    uint64_t length;
    report->GetLength(&length);
    kern_return_t ret = handleReport(mach_absolute_time(), report, uint32_t(length), kIOHIDReportTypeInput, 0);
    if (ret != kIOReturnSuccess) {
        Log("Failed to send report from device: 0x%08x", ret);
        return;
    }
}
"""
    # The original file had a trailing empty line
    with open("mac/USBDriver/USBDriver/USBDevice.cpp", "w") as f:
        f.write(content + "\n")

def write_usb_driver_lib_c():
    content = """//
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
    debugf("Err system: 0x%x\\n", err_get_system(ret));
    debugf("Err sub: 0x%x\\n", err_get_sub(ret));
    debugf("Err code: 0x%x\\n", err_get_code(ret));
}

static void notify_frame(void* refcon, IOReturn result, void** args, uint32_t numArgs) {
    kern_return_t ret = kIOReturnSuccess;
    usb_driver_device_t *device = (usb_driver_device_t *)refcon;
    
    usb_driver_hid_frame_t frame;
    size_t outputSize = sizeof(usb_driver_hid_frame_t);
    ret = IOConnectCallStructMethod(device->connection, USBDriverMethodType_GetFrame, NULL, 0, &frame, &outputSize);
    if (ret != kIOReturnSuccess) {
        debugf("Invalid return when getting frame: %d\\n", ret);
        print_return(ret);
        return;
    }

    device->receiveData(device, &frame);
}

static kern_return_t register_callback(usb_driver_device_t *device) {
    kern_return_t ret = kIOReturnSuccess;
    
    IONotificationPortRef notificationPort = IONotificationPortCreate(kIOMainPortDefault);
    if (notificationPort == NULL) {
        debugf("Failed to create notification port\\n");
        return kIOReturnError;
    }
    
    mach_port_t machNotificationPort = IONotificationPortGetMachPort(notificationPort);
    if (machNotificationPort == 0) {
        debugf("Failed to get mach notification port\\n");
        return kIOReturnError;
    }
    
    CFRunLoopSourceRef runLoopSource = IONotificationPortGetRunLoopSource(notificationPort);
    if (runLoopSource == NULL) {
        debugf("Failed to get run loop\\n");
        return kIOReturnError;
    }
    
    CFRunLoopAddSource(device->globalRunLoop, runLoopSource, kCFRunLoopDefaultMode);
    
    io_async_ref64_t asyncRef = {};
    asyncRef[kIOAsyncCalloutFuncIndex] = (io_user_reference_t)notify_frame;
    asyncRef[kIOAsyncCalloutRefconIndex] = (io_user_reference_t)device;
    ret = IOConnectCallAsyncScalarMethod(device->connection, USBDriverMethodType_NotifyFrame, machNotificationPort, asyncRef, kIOAsyncCalloutCount, NULL, 0, NULL, 0);
    if (ret != kIOReturnSuccess) {
        debugf("Failed to register callback\\n");
        return ret;
    }
    
    return kIOReturnSuccess;
}

static io_connect_t open_connection(void) {
    kern_return_t ret;
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceNameMatching(DEXT_IDENTIFIER));
    if (!service) {
        printf("USBDriverLib: Service matching '%s' not found, trying full identifier\\n", DEXT_IDENTIFIER);
        service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(FULL_DEXT_IDENTIFIER));
        if (!service) {
            debugf("Could not find matching service\\n");
            printf("USBDriverLib: Could not find matching service '%s'\\n", FULL_DEXT_IDENTIFIER);
            return IO_OBJECT_NULL;
        }
    }
    printf("USBDriverLib: Found matching service\\n");
    
    io_connect_t connection;
    ret = IOServiceOpen(service, mach_task_self_, kIOHIDServerConnectType, &connection);
    if (ret != kIOReturnSuccess) {
        debugf("Could not open connection: 0x%x\\n", ret);
        print_return(ret);
        return IO_OBJECT_NULL;
    }
    return connection;
}

usb_driver_device_t *usb_driver_init_device(usb_driver_receive_data_callback receiveData) {
    printf("USBDriverLib: usb_driver_init_device called\\n");
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
        debugf("Could not open connection\\n");
        return;
    }
    
    ret = register_callback(device);
    if (ret != kIOReturnSuccess) {
        return;
    }
    
    ret = IOConnectCallScalarMethod(device->connection, USBDriverMethodType_StartDevice, NULL, 0, NULL, 0);
    if (ret != kIOReturnSuccess) {
        debugf("IOConnectCallScalarMethod failed: 0x%08x\\n", ret);
        print_return(ret);
        return;
    }
    
    CFRunLoopRun();
    
    ret = IOServiceClose(device->connection);
    if (ret != kIOReturnSuccess) {
        debugf("Failed to close connection: 0x%08x\\n", ret);
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
        debugf("Could not send frame: 0x%x\\n", ret);
        print_return(ret);
        return;
    }
}"""
    with open("mac/USBDriver/USBDrverLib/USBDriverLib.c", "w") as f:
        f.write(content + "\n")

write_client_c()
write_usb_device_cpp()
write_usb_driver_lib_c()
