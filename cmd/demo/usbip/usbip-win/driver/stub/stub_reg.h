#pragma once

#include "stub_dev.h"

char *
reg_get_id_hw(PDEVICE_OBJECT pdo);
char *
reg_get_id_compat(PDEVICE_OBJECT pdo);
BOOLEAN
reg_get_properties(usbip_stub_dev_t *devstub);