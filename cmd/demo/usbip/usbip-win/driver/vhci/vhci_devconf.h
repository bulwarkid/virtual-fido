#pragma once

#include "devconf.h"

#include <usbdi.h>

extern NTSTATUS
setup_config(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, PUSBD_INTERFACE_INFORMATION info_intf, PVOID end_info_intf, UCHAR speed);

extern NTSTATUS
setup_intf(USBD_INTERFACE_INFORMATION *intf_info, PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, UCHAR speed);
