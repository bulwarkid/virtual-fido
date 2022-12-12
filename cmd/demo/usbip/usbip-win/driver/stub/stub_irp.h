#pragma once

#include <ntddk.h>
#include "stub_dev.h"

NTSTATUS complete_irp(IRP *irp, NTSTATUS status, ULONG info);
NTSTATUS pass_irp_down(usbip_stub_dev_t *devstub, IRP *irp, PIO_COMPLETION_ROUTINE completion_routine, void *context);
