#include "packet.h"
#include "malloc.h"
#include "string.h"

PACKET_BUFFER* alloc_packet_buffer(int len) {
	PACKET_BUFFER *buf = malloc(len);
	memset(buf, 0, len);
	if (buf == NULL)
		return NULL;
    buf->next = NULL;
	return buf;
}

void free_packet_buffer(PACKET_BUFFER *buf) {
    if(buf != NULL) {
        free(buf);
        buf = NULL;
    }
}

PACKET_LIST* create_pkt_list(int len) {
    PACKET_LIST *list = malloc(sizeof(PACKET_LIST));
    if(list == NULL) return NULL;
    list->head = NULL;
    list->tail = NULL;
    list->len = 0;
    list->max_len = len;
    return list;
}

void free_pkt_lits(PACKET_LIST *list) {
    if(list != NULL) {
        free(list);
        list = NULL;
    }
}

int pkt_insert(PACKET_LIST *list, PACKET_BUFFER *node) {
    if(list == NULL || node == NULL) return 0;
    if (list->len < list->max_len) {
        if(list->head == NULL) {
            list->head = node;
        }
        if(list->tail != NULL) {
            list->tail->next = node;
        }
        list->tail = node;
        list->len++;
        return 1;
    } else {
        return -1;
    }
}

PACKET_BUFFER* pkt_pop(PACKET_LIST *list) {
    if(list == NULL || list->len == 0 || list->head == NULL) return NULL;
    PACKET_BUFFER *buf = list->head;
    list->head = list->head->next;
    if(list->head == NULL) list->tail == NULL;
    list->len--;
    buf->next = NULL;
    return buf;
}

int get_packets_size(PACKET_LIST *list) {
    return list->len;
}