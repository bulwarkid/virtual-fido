//
//  main.cpp
//  USBDriverTester
//
//  Created by Chris de la Iglesia on 1/9/23.
//

#include <iostream>

#include "USBDriverLib.h"

static void receive_data_callback(usb_driver_device_t *device, usb_driver_hid_frame_t *frame) {
    printf("Got receive data callback with length: %llu\n", frame->length);
    printf("Data: ");
    for (int i = 0; i < frame->length; i++) {
        for (int j = 0; j < 8 ; j++) {
            uint64_t data = frame->data[i];
            printf("%02x ", uint8_t(data >> (8 * j) & 0xFF));
        }
    }
    printf("\n");
}
    
int main() {
    usb_driver_device_t *device = usb_driver_init_device(&receive_data_callback);
    
    usb_driver_start(device);
    
    return 0;
}
