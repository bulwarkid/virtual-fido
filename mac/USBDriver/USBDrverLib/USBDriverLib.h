//
//  USBDriverLib.h
//  USBDriverLib
//
//  Created by Chris de la Iglesia on 1/12/23.
//

#ifndef USBDriverLib_h
#define USBDriverLib_h

typedef struct {
    uint64_t length;
    uint64_t data[64];
} usb_driver_hid_frame;

typedef enum {
    USBDriverMethodType_SendFrame = 0,
    USBDriverMethodType_NotifyFrame = 1,
    USBDriverMethodType_GetFrame = 2,
    USBDriverMethodType_StartDevice = 3,
    USBDriverMethodType_StopDevice = 4,
    NumberOfUSBDriverMethods
} USBDriverMethodType;

#endif /* USBDriverLib_h */
