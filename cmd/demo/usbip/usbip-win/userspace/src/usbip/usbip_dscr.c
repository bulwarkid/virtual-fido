#include "usbip_windows.h"

#include "usbip_proto.h"
#include "usbip_network.h"

/* sufficient large enough seq used to avoid conflict with normal vhci operation */
static unsigned	seqnum = 0x7ffffff;

static int
fetch_descriptor(SOCKET sockfd, UINT8 dscr_type, unsigned devid, char *dscr, unsigned short dscr_size)
{
	struct usbip_header	uhdr;
	unsigned	alen;

	memset(&uhdr, 0, sizeof(uhdr));

	uhdr.base.command = htonl(USBIP_CMD_SUBMIT);
	uhdr.base.seqnum = seqnum++;
	uhdr.base.direction = htonl(USBIP_DIR_IN);
	uhdr.base.devid = htonl(devid);

	uhdr.u.cmd_submit.transfer_buffer_length = htonl(dscr_size);
	uhdr.u.cmd_submit.setup[0] = 0x80;	/* IN/control port */
	uhdr.u.cmd_submit.setup[1] = 6;		/* GetDescriptor */
	*(unsigned short *)(uhdr.u.cmd_submit.setup + 6) = (unsigned short)dscr_size;	/* Length */
	uhdr.u.cmd_submit.setup[3] = dscr_type;

	if (usbip_net_send(sockfd, &uhdr, sizeof(uhdr)) < 0) {
		dbg("fetch_descriptor: failed to send usbip header\n");
		return -1;
	}
	if (usbip_net_recv(sockfd, &uhdr, sizeof(uhdr)) < 0) {
		dbg("fetch_descriptor: failed to recv usbip header\n");
		return -1;
	}
	if (uhdr.u.ret_submit.status != 0) {
		dbg("fetch_descriptor: command submit error: %d\n", uhdr.u.ret_submit.status);
		return -1;
	}
	alen = ntohl(uhdr.u.ret_submit.actual_length);
	if (alen < dscr_size) {
		err("fetch_descriptor: too short response: actual length: %d\n", alen);
		return -1;
	}
	if (usbip_net_recv(sockfd, dscr, alen) < 0) {
		err("fetch_descriptor: failed to recv usbip payload\n");
		return -1;
	}
	return 0;
}

/* assume the length of a device descriptor is 18 */
int
fetch_device_descriptor(SOCKET sockfd, unsigned devid, char *dscr)
{
	return fetch_descriptor(sockfd, 1, devid, dscr, 18);
}

int
fetch_conf_descriptor(SOCKET sockfd, unsigned devid, char *dscr, unsigned short *plen)
{
	char	buf[9];
	unsigned short	alen;

	if (fetch_descriptor(sockfd, 2, devid, buf, 9) < 0)
		return -1;
	alen = *((unsigned short *)buf + 1);
	if (dscr == NULL) {
		*plen = alen;
		return 0;
	}
	if (*plen < alen) {
		err("fetch_conf_descriptor: too small descriptor buffer\n");
		return -1;
	}
	*plen = alen;
	return fetch_descriptor(sockfd, 2, devid, dscr, alen);
}
