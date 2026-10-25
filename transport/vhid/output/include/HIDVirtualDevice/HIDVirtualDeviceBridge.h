#ifndef HIDVirtualDeviceBridge_h
#define HIDVirtualDeviceBridge_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque handle to the virtual device
typedef void *hid_virtual_device_t;

/// Callback type for receiving HID reports from the system
typedef void (*hid_report_callback_t)(const uint8_t *data, size_t length);

/// Create a new virtual FIDO device
/// @param device_name Name of the device (e.g., "Virtual FIDO")
/// @return Device handle, or NULL on error
hid_virtual_device_t hid_virtual_device_create(const char *device_name);

/// Destroy the virtual device
/// @param device Device handle
void hid_virtual_device_destroy(hid_virtual_device_t device);

/// Send an input report to the system
/// @param device Device handle
/// @param data Report data (will be padded/truncated to 64 bytes)
/// @param length Length of data
/// @return 0 on success, -1 on error
int hid_virtual_device_send_report(hid_virtual_device_t device,
                                   const uint8_t *data, size_t length);

/// Set callback for receiving output reports from the system
/// @param device Device handle
/// @param callback Callback function
void hid_virtual_device_set_callback(hid_virtual_device_t device,
                                     hid_report_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif /* HIDVirtualDeviceBridge_h */
