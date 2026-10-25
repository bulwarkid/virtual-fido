//
//  util.cpp
//  USBDriver
//
//  Created by Chris de la Iglesia on 1/13/23.
//

#include <stdio.h>
#include <DriverKit/IOBufferMemoryDescriptor.h>
#include <DriverKit/IOLib.h>

#include "util.h"

IOBufferMemoryDescriptor *createMemoryDescriptorWithBytes(const void *bytes, uint64_t length) {
    IOBufferMemoryDescriptor *buffer;
    IOBufferMemoryDescriptor::Create(kIOMemoryDirectionInOut, length, 0, &buffer);
    buffer->SetLength(length);
    IOAddressSegment range;
    buffer->GetAddressRange(&range);
    memcpy((void*)range.address, bytes, length);
    return buffer;
}

linked_list_t *linked_list_alloc() {
    linked_list_t *list = (linked_list_t *)IOMallocZero(sizeof(linked_list_t));
    list->start = NULL;
    list->end = NULL;
    list->num_nodes = 0;
    return list;
}

void linked_list_free(linked_list_t *list) {
    if (list == NULL) {
        return;
    }
    linked_list_node *node = list->start;
    while (node != NULL) {
        linked_list_node *next = node->next;
        IOFree(node, sizeof(linked_list_node));
        node = next;
    }
    IOFree(list, sizeof(linked_list_t));
}

void linked_list_push(linked_list_t *list, void *data) {
    linked_list_node *node = (linked_list_node *)IOMallocZero(sizeof(linked_list_node));
    node->data = data;
    node->next = NULL;
    if (list->end == NULL) {
        list->start = node;
        list->end = node;
    } else {
        list->end->next = node;
        list->end = node;
    }
    list->num_nodes++;
}

void *linked_list_pop_front(linked_list_t *list) {
    if (list->start == NULL) {
        return NULL;
    }
    linked_list_node *node;
    if (list->start == list->end) {
        node = list->start;
        list->start = NULL;
        list->end = NULL;
    } else {
        node = list->start;
        list->start = list->start->next;
    }
    list->num_nodes--;
    void *data = node->data;
    IOFree(node, sizeof(linked_list_node));
    return data;
}
