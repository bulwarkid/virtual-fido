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
#include "USBDevice.h"

#define Log(fmt, ...) GlobalLog("USBDevice - " fmt, ##__VA_ARGS__)

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

char *bytesToHexString(uint8_t *address, uint64_t length) {
    char* output = (char*)IOMalloc(length * 3 + 1);
    static const char characters[] = "01234567890ABCDEF";
    for (int i = 0; i < length; i++) {
        uint8_t byte = address[i];
        output[3*i] = characters[byte >> 4];
        output[3*i+1] = characters[byte & 0x0F];
        output[3*i+2] = ' ';
    }
    output[length * 3] = '\0';
    return output;
}

kern_return_t USBDevice::setReport(IOMemoryDescriptor *report, IOHIDReportType reportType, IOOptionBits options, uint32_t completionTimeout, OSAction *action) {
    Log("setReport(%d)", reportType);
    uint64_t address;
    uint64_t length;
    report->Map(0,0,0,0,&address,&length);
    uint8_t *addressByte = reinterpret_cast<uint8_t*>(address);
    auto reportString = bytesToHexString(addressByte, length);
    Log("Report: %s", reportString);
    return kIOReturnSuccess;
}
