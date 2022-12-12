#pragma once

#include <ntdef.h>
#include <usbspec.h>

typedef USB_DEFAULT_PIPE_SETUP_PACKET	usb_cspkt_t;

USHORT get_usb_speed(USHORT bcdUSB);