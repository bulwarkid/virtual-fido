
#include "output/include/USBDriverLib/USBDriverLib.h"
#include "_cgo_export.h"

void receive_data(usb_driver_device_t *device, usb_driver_hid_frame_t *frame) {
    struct receiveDataCallback_return data = receiveDataCallback((void*)frame->data, frame->length * sizeof(uint64_t));
    int returnDataLength = data.r1;
    void *returnData = data.r0;
    if (returnDataLength > 0) {
        usb_driver_hid_frame_t frame;
        memcpy((void*)frame.data, returnData, returnDataLength);
        frame.length = returnDataLength / sizeof(uint64_t);
        usb_driver_send_frame(device, &frame);
    }
}

void start_device(void) {
    usb_driver_device_t *device = usb_driver_init_device(receive_data);
    usb_driver_start(device);
}