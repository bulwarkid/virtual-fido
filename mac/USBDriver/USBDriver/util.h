//
//  util.h
//  USBDriver
//
//  Created by Chris de la Iglesia on 12/31/22.
//

#ifndef util_h
#define util_h

#include <os/log.h>

#define GlobalLog(fmt, ...) os_log(OS_LOG_DEFAULT, "USBDriverLog - " fmt "\n", ##__VA_ARGS__)

#endif /* util_h */
