//
//  USBDriverShared.h
//  USBDriverLib
//
//  Created by Chris de la Iglesia on 1/16/23.
//

#ifndef USBDriverShared_h
#define USBDriverShared_h

typedef struct {
    uint8_t length;
    uint8_t data[64];
} usb_driver_hid_frame_t;

typedef enum {
    USBDriverMethodType_SendFrame = 0,
    USBDriverMethodType_NotifyFrame = 1,
    USBDriverMethodType_GetFrame = 2,
    USBDriverMethodType_StartDevice = 3,
    USBDriverMethodType_StopDevice = 4,
    NumberOfUSBDriverMethods
} usb_driver_method_type;

#endif /* USBDriverShared_h */
