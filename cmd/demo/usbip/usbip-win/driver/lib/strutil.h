#pragma once

#include <ntddk.h>

size_t libdrv_strlenW(LPCWSTR cwstr);
LPWSTR libdrv_strdupW(LPCWSTR cwstr);

int libdrv_snprintf(char *buf, int size, const char *fmt, ...);
int libdrv_snprintfW(PWCHAR buf, int size, LPCWSTR fmt, ...);
int libdrv_asprintfW(PWCHAR *pbuf, LPCWSTR fmt, ...);

VOID libdrv_free(PVOID data);