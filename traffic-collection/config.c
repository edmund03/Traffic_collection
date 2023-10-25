#include "sys/io.h"
#include "sys/stat.h"
#include "sys/types.h"

#include "config.h"
#include "error.h"
#include "util.h"
#include "log.h"

static bool is_line_valid(char *buf);
static bool pattern_match(char *pattern, char *match);
static bool *check_config_file_exist(char *path);
static void format_app_name(char app_name[]);

static void close_default_config_file(FILE *file)
{
    if (file != NULL)
    {
        fclose(file);
    }
}

static traffic_config *create_config(size_t category_size, char *filepath)
{
    if (category_size <= 0)
        return NULL;
    traffic_config *config = (traffic_config *)malloc(sizeof(traffic_config) + sizeof(app_info *) * (CATEGORY_MAX_NUM + 1));
    if (config == NULL)
    {
        printf("alloc traffic config fail!\n");
        return config;
    }
    config->app_max_index = CATEGORY_MAX_NUM;
    memcpy(config->basepath, filepath, strlen(filepath));
    for (int i = 0; i <= config->app_max_index; i++)
    {
        config->app_infos[i] = NULL;
    }
    
    return config;
}

static int get_pcap_file_path(char filepath[])
{
    FILE *config_file;
    // open default config
    if (check_config_file_exist(DEFAULT_CONFIG_PATH))
    {
        config_file = fopen(DEFAULT_CONFIG_PATH, "r");
        if (config_file != NULL)
        {
            char line[1000];
            while (fgets(line, sizeof(line), config_file) != NULL)
            {
                sscanf(line, "pcapPath=%s\n", filepath);
                if (!strIsEmpty(filepath))
                    break;
            }
            fclose(config_file);
        }
    }
    if (strIsEmpty(filepath))
    {
        memcpy(filepath, PCAP_DEFAULT_PATH, strlen(PCAP_DEFAULT_PATH));
    }
    // check and mkdir pcap folder
    return mkdir_folder(filepath);
}

traffic_config *load_category_config()
{
    traffic_config *config = NULL;
    FILE *category_file;
    char filepath[PCAP_MAX_FILE_PATH];
    if (get_pcap_file_path(filepath) != OPERATION_OK)
    {
        log_write(ERROR, "mkdir pcap folder %s fail!\n", filepath);
        return NULL;
    }
    // open category config
    if (check_config_file_exist(DEFAULT_APP_CATEGORY_PATH))
    {
        category_file = fopen(DEFAULT_APP_CATEGORY_PATH, "r");
        log_write(ERROR, "read category from %s...\n", DEFAULT_APP_CATEGORY_PATH);
    }
    if (category_file == NULL)
    {
        log_write(ERROR, "open category file %s fail!\n", DEFAULT_APP_CATEGORY_PATH);
        return NULL;
    }
    char line[1000];
    int len, max_index;
    fscanf(category_file, "%d %d", &len, &max_index);
    app_info *infos[max_index + 1];
    char app_name[100];
    while (fgets(line, sizeof(line), category_file) != NULL)
    {
        if (is_line_valid(line))
        {
            sscanf(line, "%[^:]", app_name);
            uint16_t index = atoi(line + strlen(app_name) + 1);
            if (index == 0)
                continue;
            // handle app name
            format_app_name(app_name);
            app_info *info = (app_info *)malloc(sizeof(app_info));
            memset(info->name, 0, sizeof(info->name));
            memcpy(info->name, app_name, strlen(app_name));
            memset(info->path, 0, sizeof(info->path));
            strcat(info->path, filepath);
            strcat(info->path, "/");
            strcat(info->path, info->name);
            strcat(info->path, PCAP_FILE_SUFFIX);
            info->out_pcap = NULL;
            infos[index] = info;
            max_index = max_index > index ? max_index : index;
            log_write(INFO, "capture %s, app id: %d, storage: %s\n", app_name, index, info->path);
        }
    }
    close_default_config_file(category_file);
    config = create_config(len, filepath);
    if (config != NULL)
    {
        for (int i = 0; i <= max_index; i++)
        {
            config->app_infos[i] = infos[i];
        }
    }
    return config;
}

void free_traffic_config(traffic_config **config)
{
    if (config == NULL || *config == NULL)
        return;

    for (int i = 0; i < (*config)->app_max_index; i++)
    {
        if ((*config)->app_infos[i] != NULL)
        {
            if ((*config)->app_infos[i]->out_pcap != NULL)
            {
                pcap_dump_close((*config)->app_infos[i]->out_pcap);
            }
            free((void *)((*config)->app_infos[i]));
            (*config)->app_infos[i] = NULL;
        }
    }
    free((void *)(*config));
    *config = NULL;
}

/*******************************utils*****************************************/

static bool is_line_valid(char *buf)
{
    if (buf[0] == '#' || buf[0] == '\n' || strchr(buf, ':') == NULL)
    {
        return false;
    }
    char *pattern = "^.*:[0-9]+$";
    return pattern_match(pattern, buf);
}

static bool pattern_match(char *pattern, char *match)
{
    if (strIsEmpty(pattern) || strIsEmpty(match))
        return false;
    regex_t preg;
    if (regcomp(&preg, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB | REG_NEWLINE) != 0)
    {
        log_write(ERROR, "pattern compile fail!\n");
        return false;
    }
    size_t nmatch = 1;
    regmatch_t pmatch[1];
    int err_code = regexec(&preg, match, nmatch, pmatch, REG_NOTEOL);
    if (err_code != REG_NOERROR) //匹配失败，打印失败原因
    {
        int err_length = regerror(err_code, &preg, NULL, 0); //先获取失败原因的长度，然后再开辟内存空间存放。
        char *errbuf = malloc(err_length);
        regerror(err_code, &preg, errbuf, err_length);
        log_write(INFO, "%s\n", errbuf);
        free(errbuf);
        regfree(&preg);
        return false;
    }
    regfree(&preg);
    return true;
}

static bool *check_config_file_exist(char *path)
{
    if (strIsEmpty(path) || (access(path, R_OK) != 0))
        return false;
    return true;
}

static bool is_char_not_letter(char c)
{
    if (c == ' ' || c == '-' || c == '_')
        return true;
    return false;
}

static void format_app_name(char app_name[])
{
    if (strIsEmpty(app_name))
        return;
    int left = 0, len = strlen(app_name), index = 0;
    while (index < len)
    {
        if (is_char_not_letter(app_name[index]))
        {
            if ((index + 1) < len)
            {
                if (is_char_not_letter(app_name[index + 1]))
                {
                    index++;
                }
                else
                {
                    app_name[left++] = '_';
                    index++;
                }
            }
            else
            {
                break;
            }
        }
        else
        {
            app_name[left++] = tolower(app_name[index++]);
        }
    }
    app_name[left] = '\0';
}

app_info *create_app_info(uint16_t app_index)
{
    app_info *info = (app_info *)malloc(sizeof(app_info));
    char app_name[8];
    Int2String(app_index, app_name);
    // printf("new app name:%s\n", app_name);
    memset(info->name, 0, sizeof(info->name));
    memcpy(info->name, app_name, strlen(app_name));
    memset(info->path, 0, sizeof(info->path));
    char filepath[PCAP_MAX_FILE_PATH];
    get_pcap_file_path(filepath);
    strcat(info->path, filepath);
    strcat(info->path, "/");
    strcat(info->path, info->name);
    strcat(info->path, PCAP_FILE_SUFFIX);
    info->out_pcap = NULL;
    return info;
}