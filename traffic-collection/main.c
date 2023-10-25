
#include "stdio.h"
#include "signal.h"
#include "string.h"

#include "config.h"
#include "error.h"
#include "packet.h"
#include "params.h"
#include "log.h"
#include "util.h"

/**
struct pcap_pkthdr {
	struct timeval ts; // timestamp
	bpf_u_int32 caplen; // length of portion present
	bpf_u_int32 len; // length this packet (off wire)
};
*/

pcap_t *pcap_handle;
traffic_config *config;
size_t cache_size = 0;

static void packet_flush_all();
static pcap_t *init_pcap_interface()
{
	pcap_t *handle;
	char error_content[PCAP_ERRBUF_SIZE];
	/*打开网络接口*/
	handle = pcap_open_live(CAPTURE_NET_INTERFACE,
							CAPTURE_PACKET_MAX_SNAPLEN,
							1,	  /*混杂模式*/
							1000, /*等待时间， 0表示一直等待直到数据包到来*/
							error_content);
	if (handle == NULL)
	{
		log_write(ERROR, "init_pcap_interface fail:%s\n", error_content);
		return handle;
	}
	// Set filter: vlan
	struct bpf_program filter_options;
	pcap_compile(handle, &filter_options, "vlan", 1, 0);
	pcap_setfilter(handle, &filter_options);
	return handle;
}

static void init_pcap_dumper()
{
	pcap_dumper_t *out_pcap;
	for (int i = 0; i <= config->app_max_index; i++)
	{
		if (config->app_infos[i] == NULL)
			continue;
		out_pcap = pcap_dump_open_append(pcap_handle, config->app_infos[i]->path);
		if (out_pcap != NULL)
		{
			config->app_infos[i]->out_pcap = out_pcap;
			out_pcap = NULL;
		}
		else
		{
			log_write(ERROR, "open dump file fail:%s!\n", config->app_infos[i]->name);
		}
	}
}

static int init()
{
	config = load_category_config();
	if (config == NULL)
	{
		log_write(ERROR, "config file not exists or parse failure!\n");
		return ERROR_DEFAULT_CONFIG_LOAD_FAIL;
	}
	pcap_handle = init_pcap_interface();
	if (pcap_handle == NULL)
	{
		log_write(ERROR, "open network device failure!\n");
		return ERROR_PCAP_INTREFACE_CREATE_FAIL;
	}
	init_pcap_dumper();
	
	return OPERATION_OK;
}

static void close_pcap()
{
	if (pcap_handle != NULL)
	{
		pcap_close(pcap_handle);
		pcap_handle = NULL;
	}
}

static void packet_flush(uint8_t app_index, struct pcap_pkthdr *pkthdr, u_char *packet)
{
	// config is null
	if (config == NULL)
	{
		config = load_category_config();
		if (config == NULL)
		{
			log_write(ERROR, "load config info fail!\n");
			return;
		}
	}
	// app index invalid
	if (app_index <= 0 || (app_index > config->app_max_index && app_index != PKT_UNTAGGED_VLAN_ID))
	{
		// index not exists, drop packets
		return;
	}
	if (config->app_infos[app_index] == NULL)
	{
		// new app category, use vlan id as file name to create new app_info
		config->app_infos[app_index] = create_app_info(app_index);
		if (config->app_infos[app_index] == NULL)
		{
			log_write(ERROR, "new app id: %d create fail!\n", app_index);
			return;
		}
		else
		{
			log_write(INFO, "capture %s, app id: %d, storage: %s\n", config->app_infos[app_index]->name, app_index, config->app_infos[app_index]->path);
		}
	}
	pcap_dumper_t *out_pcap = config->app_infos[app_index]->out_pcap;
	if (!check_file_exist(config->app_infos[app_index]->path)) // file not exists
	{
		// create file & folder
		if (mkdir_folder(config->basepath) != OPERATION_OK)
		{
			log_write(ERROR, "create pcap folder %s fail!\n", config->basepath);
			return;
		}
		FILE *file = fopen(config->app_infos[app_index]->path, "a+");
		if (file == NULL)
		{
			log_write(ERROR, "create file %s fail!\n", config->app_infos[app_index]->path);
			return;
		}
		else
		{
			fclose(file);
			file = NULL;
		}
		// update out_pcap
		out_pcap = pcap_dump_open_append(pcap_handle, config->app_infos[app_index]->path);
		if (out_pcap == NULL)
		{
			log_write(ERROR, "create out_pcap fail!\n");
			return;
		}
		config->app_infos[app_index]->out_pcap = out_pcap;
	}
	else if (out_pcap == NULL) // out_pcap entry null
	{
		out_pcap = pcap_dump_open_append(pcap_handle, config->app_infos[app_index]->path);
		if (out_pcap == NULL)
		{
			log_write(ERROR, "create out_pcap fail!\n");
			return;
		}
		config->app_infos[app_index]->out_pcap = out_pcap;
	}

	pcap_dump((u_char *)out_pcap, pkthdr, packet);
	cache_size += sizeof(struct pcap_pkthdr) + pkthdr->caplen;
	if (cache_size > 1000)
	{
		cache_size = 0;
		packet_flush_all();
	}
}

static void packet_callback(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	// printf("call packet_callback\n");
	if (pkthdr->caplen < pkthdr->len)
	{
		return; // 丢包，捕获不完整
	}
	// decap
	uint8_t app_index = PKT_GET_VLAN_APP_ID(packet);
	// printf("packet vlan app id:%d\n", app_index);
	if (app_index == PKT_UNTAGGED_VLAN_ID)
	{
		// call snort3 api
		// printf("call snorts api\n");
		return;
	}
	// printf("app_index:%d\n", app_index);
	if (app_index <= 0 || app_index > config->app_max_index)
		return; // drop packet
	else
	{
		// printf("packet vlan id:%d, packet captured:%d\n", app_index, pkthdr->caplen);
		// dump_pkt((char *)packet, pkthdr->caplen);
		struct pcap_pkthdr *new_pkthdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
		memcpy(new_pkthdr, pkthdr, sizeof(struct pcap_pkthdr));
		new_pkthdr->caplen = pkthdr->caplen - PKT_VLAN_TAG_LEN;
		new_pkthdr->len = pkthdr->len - PKT_VLAN_TAG_LEN;
		char *new_packet = (char *)malloc(new_pkthdr->caplen);
		memcpy(new_packet, packet, PKT_VLAN_TAG_OFFSET);
		memcpy(new_packet + PKT_VLAN_TAG_OFFSET, packet + PKT_VLAN_TAG_OFFSET + PKT_VLAN_TAG_LEN, new_pkthdr->caplen - PKT_VLAN_TAG_OFFSET);
		packet_flush(app_index, new_pkthdr, new_packet);
		free((void *)new_pkthdr);
		pkthdr = NULL;
		free((void *)new_packet);
		packet = NULL;
	}
}

static void loop()
{
	while (pcap_dispatch(pcap_handle,			//回调函数
						 CAPTURE_LOOP_INFINITY, // loop infinity
						 packet_callback,		//回调函数
						 NULL) >= 0)			// pass arguments to callback
	{
	}
}

static void packet_flush_all()
{
	if (config != NULL)
	{
		for (int i = 0; i <= config->app_max_index; i++)
		{
			if (config->app_infos[i] != NULL && config->app_infos[i]->out_pcap != NULL)
			{
				pcap_dump_flush(config->app_infos[i]->out_pcap);
			}
		}
	}
}

static void stop()
{
	log_write(INFO, "stop packet capture:%s\n", CAPTURE_NET_INTERFACE);
	packet_flush_all();
	free_traffic_config(&config);
	close_pcap();
	return;
}

static void start()
{
	stop();
	log_write(INFO, "start packet capture:%s\n", CAPTURE_NET_INTERFACE);
	int res = init();
	if (res != OPERATION_OK)
	{
		log_write(ERROR, "initial fail!\n");
		return;
	}

	signal(SIGINT, stop);  // ctrl+c end process
	signal(SIGTSTP, stop); // ctrl+z end process
	signal(SIGTERM, stop);
	loop();
	close_pcap();
}

static void restart()
{
	stop();
	start();
}

int main(int argc, char const *argv[])
{
	if (argc > 1)
	{
		if (strcmp("start", argv[1]) == 0)
		{
			// start service
			start();
		}
		else if (strcmp("reload", argv[1]) == 0)
		{
			restart();
		}
	}
	else
	{
		start();
	}
	return 0;
}