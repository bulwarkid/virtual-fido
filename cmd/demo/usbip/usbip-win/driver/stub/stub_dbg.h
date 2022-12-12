#pragma once

#define DRVPREFIX	"usbip_stub"
#include "dbgcommon.h"
#include "dbgcode.h"
#include "stub_dev.h"

#ifdef DBG

#include "stub_devconf.h"

/* NOTE: LSB cannot be used, which is system-wide mask. Thus, DBG_XXX start from 0x0002 */
#define DBG_GENERAL	0x0002
#define DBG_DISPATCH	0x0004
#define DBG_DEV		0x0008
#define DBG_IOCTL	0x0010
#define DBG_READWRITE	0x0020
#define DBG_PNP		0x0040
#define DBG_POWER	0x0080
#define DBG_DEVCONF	0x0100

const char *dbg_device(PDEVICE_OBJECT devobj);
const char *dbg_devices(PDEVICE_OBJECT devobj, BOOLEAN is_attached);
const char *dbg_devstub(usbip_stub_dev_t *devstub);

const char *dbg_stub_ioctl_code(ULONG ioctl_code);

#endif
