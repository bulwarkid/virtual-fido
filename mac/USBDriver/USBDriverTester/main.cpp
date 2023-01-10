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

int main() {
    printf("Looking for %s...\n", dextIdentifier);
    kern_return_t ret = kIOReturnSuccess;
    
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
    
    ret = IOConnectCallScalarMethod(connection, 0, nullptr, 0, nullptr, 0);
    if (ret != kIOReturnSuccess) {
        printf("IOConnectCallScalarMethod failed: 0x%08x\n", ret);
        return 1;
    }
    
    getchar();
    
    ret = IOServiceClose(connection);
    if (ret != kIOReturnSuccess) {
        printf("Failed to close connection: 0x%08x\n", ret);
        return 1;
    }
    
    return 0;
}
