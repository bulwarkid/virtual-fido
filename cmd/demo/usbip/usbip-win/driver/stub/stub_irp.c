#include "stub_driver.h"
#include "stub_dbg.h"
#include "stub_dev.h"

NTSTATUS
complete_irp(IRP *irp, NTSTATUS status, ULONG info)
{
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS
pass_irp_down(usbip_stub_dev_t *devstub, IRP *irp, PIO_COMPLETION_ROUTINE completion_routine, void *context)
{
	if (completion_routine) {
		IoCopyCurrentIrpStackLocationToNext(irp);
		IoSetCompletionRoutine(irp, completion_routine, context, TRUE, TRUE, TRUE);
	}
	else {
		IoSkipCurrentIrpStackLocation(irp);
	}

	return IoCallDriver(devstub->next_stack_dev, irp);
}
