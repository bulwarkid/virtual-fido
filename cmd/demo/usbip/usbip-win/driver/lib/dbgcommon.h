#pragma once

#include <ntddk.h>

/* DPFLTR_SYSTEM_ID emits too many unrelated kernel logs */
#define MY_DPFLTR	DPFLTR_IHVDRIVER_ID

#ifdef DBG

#include "usbip_proto.h"

#define DBGE(part, fmt, ...)	DbgPrintEx(MY_DPFLTR, 0x01000000 | (part), DRVPREFIX ":(EE) " fmt, ## __VA_ARGS__)
#define DBGW(part, fmt, ...)	DbgPrintEx(MY_DPFLTR, 0x02000000 | (part), DRVPREFIX ":(WW) " fmt, ## __VA_ARGS__)
#define DBGI(part, fmt, ...)	DbgPrintEx(MY_DPFLTR, 0x04000000 | (part), DRVPREFIX ": " fmt, ## __VA_ARGS__)

const char *dbg_usbip_hdr(struct usbip_header *hdr);
const char *dbg_command(UINT32 command);

#else

#define DBGE(part, fmt, ...)
#define DBGW(part, fmt, ...)
#define DBGI(part, fmt, ...)

#endif	

#define ERROR(fmt, ...)	DbgPrintEx(MY_DPFLTR, 0xffffffff, DRVPREFIX ":(EE) " fmt, ## __VA_ARGS__)
#define INFO(fmt, ...)	DbgPrintEx(MY_DPFLTR, 0xffffffff, DRVPREFIX ": " fmt, ## __VA_ARGS__)
