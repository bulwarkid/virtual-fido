//
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

