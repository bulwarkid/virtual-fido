#ifndef _USBIP_DSCR_H_
#define _USBIP_DSCR_H_

#include <WinSock2.h>

extern int
fetch_device_descriptor(SOCKET sockfd, unsigned devid, char *dscr);
extern int
fetch_conf_descriptor(SOCKET sockfd, unsigned devid, char *dscr, unsigned short *plen);

#endif /* _USBIP_DSCR_H_ */
