#include "vhci.h"

extern NTSTATUS	irp_pass_down(PDEVICE_OBJECT devobj, PIRP irp);
extern NTSTATUS	irp_send_synchronously(PDEVICE_OBJECT devobj, PIRP irp);
extern NTSTATUS	irp_success(PIRP irp);
extern NTSTATUS	irp_done(PIRP irp, NTSTATUS status);