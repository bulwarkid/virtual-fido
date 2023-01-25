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

IOBufferMemoryDescriptor *createMemoryDescriptorWithBytes(const void *bytes, uint64_t length);

struct linked_list_node {
    void *data;
    linked_list_node *next;
};

typedef struct {
    linked_list_node *start;
    linked_list_node *end;
    uint32_t num_nodes;
} linked_list_t;

linked_list_t *linked_list_alloc();
void linked_list_free(linked_list_t *list);
void linked_list_push(linked_list_t *list, void *data);
void* linked_list_pop_front(linked_list_t *list);

#endif /* util_h */
