
#include "output/include/USBDriverLib/USBDriverLib.h"
#include "_cgo_export.h"

static usb_driver_device_t *device;

void receive_data(usb_driver_device_t *device, usb_driver_hid_frame_t *frame) {
    receiveDataCallback(frame->data, frame->length);
}

void send_data(void *data, int length) {
    usb_driver_hid_frame_t frame;
    memcpy(frame.data, data, length);
    frame.length = length;
    usb_driver_send_frame(device, &frame);
}

void start_device(void) {
    device = usb_driver_init_device(receive_data);
    usb_driver_start(device);
}