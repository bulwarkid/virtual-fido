#include "vhci_driver.h"
#include "vhci_queue_hc.tmh"

extern VOID io_device_control(_In_ WDFQUEUE queue, _In_ WDFREQUEST req,
	_In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode);
extern VOID io_read(_In_ WDFQUEUE queue, _In_ WDFREQUEST req, _In_ size_t len);
extern VOID io_write(_In_ WDFQUEUE queue, _In_ WDFREQUEST req, _In_ size_t len);

static VOID
io_default_hc(_In_ WDFQUEUE queue, _In_ WDFREQUEST req)
{
	UNREFERENCED_PARAMETER(queue);
	UNREFERENCED_PARAMETER(req);

	TRE(QUEUE_HC, "unexpected io default callback");
}

PAGEABLE NTSTATUS
create_queue_hc(pctx_vhci_t vhci)
{
	WDFQUEUE	queue;
	WDF_IO_QUEUE_CONFIG	conf;
	WDF_OBJECT_ATTRIBUTES	attrs;
	NTSTATUS	status;

	PAGED_CODE();

	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&conf, WdfIoQueueDispatchParallel);
	conf.EvtIoRead = io_read;
	conf.EvtIoWrite = io_write;
	conf.EvtIoDeviceControl = io_device_control;
	conf.EvtIoDefault = io_default_hc;

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, pctx_vhci_t);
	attrs.SynchronizationScope = WdfSynchronizationScopeQueue;
	attrs.ExecutionLevel = WdfExecutionLevelPassive;
	status = WdfIoQueueCreate(vhci->hdev, &conf, &attrs, &queue);
	if (NT_SUCCESS(status)) {
		*TO_PVHCI(queue) = vhci;
		vhci->queue = queue;
	}
	else {
		TRE(QUEUE_HC, "failed to create queue: %!STATUS!", status);
	}
	return status;
}
