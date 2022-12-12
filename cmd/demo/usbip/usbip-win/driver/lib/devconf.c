#include "devconf.h"

#include <usbdlib.h>

PUSB_INTERFACE_DESCRIPTOR
dsc_find_first_intf(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf)
{
	return (PUSB_INTERFACE_DESCRIPTOR)USBD_ParseDescriptors(dsc_conf, dsc_conf->wTotalLength, dsc_conf, USB_INTERFACE_DESCRIPTOR_TYPE);
}

PUSB_INTERFACE_DESCRIPTOR
dsc_find_intf(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, UCHAR intf_num, USHORT alt_setting)
{
	return USBD_ParseConfigurationDescriptorEx(dsc_conf, dsc_conf, intf_num, alt_setting, -1, -1, -1);
}

static BOOLEAN
intf_has_matched_ep(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, PUSB_INTERFACE_DESCRIPTOR dsc_intf, PUSB_ENDPOINT_DESCRIPTOR dsc_ep)
{
	PVOID	start = dsc_intf;
	PUSB_ENDPOINT_DESCRIPTOR	dsc_ep_try;
	UCHAR	n_ep = dsc_intf->bNumEndpoints;

	while (n_ep > 0) {
		dsc_ep_try = dsc_next_ep(dsc_conf, start);
		if (dsc_ep_try == NULL)
			break;
		if (dsc_ep->bLength == dsc_ep_try->bLength) {
			if (RtlCompareMemory(dsc_ep, dsc_ep_try, dsc_ep->bLength) == dsc_ep->bLength)
				return TRUE;
		}
		start = dsc_ep_try;
		n_ep--;
	}
	return FALSE;
}

PUSB_INTERFACE_DESCRIPTOR
dsc_find_intf_by_ep(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, PUSB_ENDPOINT_DESCRIPTOR dsc_ep)
{
	PVOID	start = dsc_conf;

	while (start != NULL) {
		PUSB_INTERFACE_DESCRIPTOR	dsc_intf;

		dsc_intf = (PUSB_INTERFACE_DESCRIPTOR)USBD_ParseDescriptors(dsc_conf, dsc_conf->wTotalLength, start, USB_INTERFACE_DESCRIPTOR_TYPE);
		if (dsc_intf == NULL)
			break;
		if (intf_has_matched_ep(dsc_conf, dsc_intf, dsc_ep))
			return dsc_intf;
		start = NEXT_DESC(dsc_intf);
	}
	return NULL;
}

PUSB_ENDPOINT_DESCRIPTOR
dsc_find_intf_ep(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, PUSB_INTERFACE_DESCRIPTOR dsc_intf, UCHAR epaddr)
{
	PVOID	start = dsc_intf;
	PUSB_ENDPOINT_DESCRIPTOR	dsc_ep;
	int	i;

	for (i = 0; i < dsc_intf->bNumEndpoints; i++) {
		dsc_ep = dsc_next_ep(dsc_conf, start);
		if (dsc_ep == NULL)
			return NULL;
		if (dsc_ep->bEndpointAddress == epaddr)
			return dsc_ep;
	}
	return NULL;
}

PUSB_ENDPOINT_DESCRIPTOR
dsc_next_ep(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf, PVOID start)
{
	PUSB_COMMON_DESCRIPTOR	dsc = (PUSB_COMMON_DESCRIPTOR)start;
	if (dsc->bDescriptorType == USB_ENDPOINT_DESCRIPTOR_TYPE)
		dsc = NEXT_DESC(dsc);
	return (PUSB_ENDPOINT_DESCRIPTOR)USBD_ParseDescriptors(dsc_conf, dsc_conf->wTotalLength, dsc, USB_ENDPOINT_DESCRIPTOR_TYPE);
}

ULONG
dsc_conf_get_n_intfs(PUSB_CONFIGURATION_DESCRIPTOR dsc_conf)
{
	PVOID	start = dsc_conf;
	ULONG	n_intfs = 0;

	while (start != NULL) {
		PUSB_COMMON_DESCRIPTOR	desc = USBD_ParseDescriptors(dsc_conf, dsc_conf->wTotalLength, start, USB_INTERFACE_DESCRIPTOR_TYPE);
		if (desc == NULL)
			break;
		start = NEXT_DESC(desc);
		n_intfs++;
	}
	return n_intfs;
}
