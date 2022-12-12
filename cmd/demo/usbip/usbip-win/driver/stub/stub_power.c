/* libusb-win32, Generic Windows USB Library
 * Copyright (c) 2002-2005 Stephan Meyer <ste_meyer@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "stub_driver.h"
#include "stub_dbg.h"

NTSTATUS
stub_dispatch_power(usbip_stub_dev_t *devstub, IRP *irp)
{
	NTSTATUS	status;

	status = lock_dev_removal(devstub);
	if (NT_ERROR(status)) {
		irp->IoStatus.Status = status;
		PoStartNextPowerIrp(irp);
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	/* pass all other power IRPs down without setting a completion routine */
	PoStartNextPowerIrp(irp);
	IoSkipCurrentIrpStackLocation(irp);
	status = PoCallDriver(devstub->next_stack_dev, irp);
	unlock_dev_removal(devstub);

	return status;
}