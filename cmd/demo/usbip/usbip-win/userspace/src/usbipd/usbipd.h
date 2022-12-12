#pragma once

#include <winsock2.h>
#include <windows.h>

#include "usbip_common.h"

extern int recv_request_import(SOCKET sockfd);
extern int recv_request_devlist(SOCKET connfd);