#ifndef __CONFIG_H
#define __CONFIG_H

#include "stdio.h"
#include "stdlib.h"
#include "stddef.h"
#include "stdbool.h"
#include "string.h"
#include "pcap.h"
#include "unistd.h"
#include "regex.h"

#define CAPTURE_NET_INTERFACE "eth2"

#define DEFAULT_APP_CATEGORY_PATH "/etc/traffic/category.conf"
#define DEFAULT_CONFIG_PATH "/etc/traffic/default.conf"
#define PCAP_DEFAULT_PATH "/opt/traffic/pcap"
#define PCAP_FILE_SUFFIX ".pcap"
#define PCAP_MAX_FILE_PATH (512)
#define PCAP_MAX_FILE_NAME (50)

#define PCAP_FILE_DRFAULT_MAX_SIZE 500 // MB

#define CAPTURE_PACKET_MAX_SNAPLEN 65535
#define CAPTURE_WAITING_TIME 1000 // ms
#define CAPTURE_LOOP_INFINITY 10
#define CAPTURE_MAX_CACHE_SZIE  1000// byte:10 * 1024 * 1024

#define CATEGORY_MAX_NUM 255

typedef struct app_info
{
    uint16_t index;          // app index -- vlan id
    char name[200];          // app name
    char path[200];          // pcap file path
    pcap_dumper_t *out_pcap; // file pointer
} app_info;

typedef struct traffic_config
{
    // size_t cache_size; // MB
    // int single_file_size; //MB
    char basepath[PCAP_MAX_FILE_PATH]; //pcap_base_path
    // size_t app_size;
    uint16_t app_max_index;
    app_info *app_infos[];
} traffic_config;

traffic_config *load_category_config();

void free_traffic_config(traffic_config **config);

app_info *create_app_info(uint16_t app_index);

#endif
