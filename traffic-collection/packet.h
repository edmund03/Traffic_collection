#ifndef __PACKET_H
#define __PACKET_H

#include "stddef.h"

#define PKT_VLAN_TAG_LEN 4
#define PKT_VLAN_TAG_OFFSET 12
#define PKT_VLAN_ID_APP_OFFSET 15
#define PKT_GET_VLAN_APP_ID(p) (*(((uint8_t *)p) + PKT_VLAN_ID_APP_OFFSET))

#define PKT_UNTAGGED_VLAN_ID 0xFF

/*
 * packet node
 */
typedef struct packet_buffer
{
    struct packet_buffer *next;
    void *data;
    size_t pkt_size;
} PACKET_BUFFER;

/*
 * packet node
 */
typedef struct packet_list
{
    PACKET_BUFFER *head;
    PACKET_BUFFER *tail;
    int len;
    int max_len;
} PACKET_LIST;

PACKET_LIST *create_pkt_list(int len);
void free_pkt_lits(PACKET_LIST *list);

int pkt_insert(PACKET_LIST *list, PACKET_BUFFER *node);
PACKET_BUFFER *pkt_pop(PACKET_LIST *list);
int get_packets_size(PACKET_LIST *list);

PACKET_BUFFER *alloc_packet_buffer(int len);
void free_packet_buffer(PACKET_BUFFER *buf);

#endif