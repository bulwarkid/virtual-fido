//
//  USBDriverLib.h
//  USBDriverLib
//
//  Created by Chris de la Iglesia on 1/12/23.
//

#ifndef USBDriverLib_h
#define USBDriverLib_h

#ifdef __cplusplus
extern "C" {
#endif

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOTypes.h>

#include "USBDriverShared.h"


struct usb_driver_device_s;
typedef struct usb_driver_device_s usb_driver_device_t;
typedef void (*usb_driver_receive_data_callback)(usb_driver_device_t   *,usb_driver_hid_frame_t*);


struct usb_driver_device_s {
    usb_driver_receive_data_callback receiveData;
    CFRunLoopRef globalRunLoop;
    io_connect_t connection;
};

usb_driver_device_t *usb_driver_init_device(usb_driver_receive_data_callback receiveData);
void usb_driver_start(usb_driver_device_t *device);
void usb_driver_stop(usb_driver_device_t *device);
void usb_driver_send_frame(usb_driver_device_t *device, usb_driver_hid_frame_t *frame);

#ifdef __cplusplus
}
#endif

#endif /* USBDriverLib_h */
