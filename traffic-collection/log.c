#include "sys/stat.h"
#include "sys/types.h"

#include "log.h"
#include "error.h"
#include "config.h"
#include "util.h"
#define MAXLEVELNUM (3)

static LOGSET logsetting = {LOG_SETTING_UNINITIALIZED, ""};
static LOG loging;

const static char LogLevelText[4][10] = {"INFO", "DEBUG", "WARN", "ERROR"};

static char *getdate(char *date);

static unsigned char getcode(char *path)
{
    unsigned char code = 255;
    if (strcmp("INFO", path) == 0)
        code = 1;
    else if (strcmp("WARN", path) == 0)
        code = 3;
    else if (strcmp("ERROR", path) == 0)
        code = 4;
    else if (strcmp("NONE", path) == 0)
        code = 0;
    else if (strcmp("DEBUG", path) == 0)
        code = 2;
    return code;
}

static unsigned char read_logpath(char *path)
{
    char value[512] = {0x0};
    memcpy(value, path, strlen(path));
    char data[50] = {0x0};
    getdate(data);
    strcat(data, ".log");
    strcat(value, "/");
    strcat(value, data);
    if (strcmp(value, logsetting.filepath) != 0)
        memcpy(logsetting.filepath, value, strlen(value));
    memset(value, 0, sizeof(value));
    memset(data, 0, sizeof(data));
}

static void read_config(char *path)
{
    char line[512] = {0x0};
    char value[512] = {0x0};
    char data[50] = {0x0};

    FILE *fpath = fopen(path, "r");
    if (fpath == NULL)
    {
        read_logpath(LOG_DEFAULT_PATH);
    }
    else
    {
        while (fgets(line, sizeof(line), fpath) != NULL)
        {
            sscanf(line, "logPath=%s\n", value);
            if (!strIsEmpty(value))
                break;
        }
        if (strIsEmpty(value))
            read_logpath(LOG_DEFAULT_PATH);
        else
            read_logpath(value);
        fclose(fpath);
    }
}
/*
 *日志设置信息
 * */
static LOGSET *getlogset()
{
    if (logsetting.initialized == LOG_SETTING_UNINITIALIZED)
    {
        read_config(DEFAULT_CONFIG_PATH);
        logsetting.initialized = LOG_SETTING_INITIALIZED;
    }
    return &logsetting;
}

/*
 *获取日期
 * */
static char *getdate(char *date)
{
    time_t timer = time(NULL);
    strftime(date, 11, "%Y-%m-%d", localtime(&timer));
    return date;
}

/*
 *获取时间
 * */
static void settime()
{
    time_t timer = time(NULL);
    strftime(loging.logtime, 20, "%Y-%m-%d %H:%M:%S", localtime(&timer));
}

static int create_log_file(char *path)
{
    if (strIsEmpty(path) || path[0] != '/')
        return LOG_FILE_PATH_ERROR;
    char current[MAXFILEPATH] = {0}, folder_path[MAXFILEPATH] = {0};
    int offset = 1, len = strlen(path);
    while (true)
    {
        sscanf(path + offset, "%[^/]", current);
        if (strIsEmpty(current) || (offset + strlen(current)) >= len)
            break;
        memcpy(folder_path + strlen(folder_path), "/", 1);
        memcpy(folder_path + strlen(folder_path), current, strlen(current));
        if ((access(folder_path, F_OK) != 0) && (mkdir(folder_path, 0777) != 0))
        {
            printf("create log path fail!\n");
            return LOG_FILE_PATH_CREATE_ERROR;
        }
        offset += strlen(current) + 1;
    }
    return OPERATION_OK;
}

static int initlog(unsigned char loglevel)
{
    char strdate[30] = {0x0};
    LOGSET *logsetting;
    //获取日志配置信息
    logsetting = getlogset();

    memset(&loging, 0, sizeof(LOG));
    //获取日志时间
    settime();
    memcpy(loging.filepath, logsetting->filepath, MAXFILEPATH);
    //检查日志文件的路径存在
    int res = create_log_file(loging.filepath);
    if (res != OPERATION_OK)
        return res;
    if (loging.logfile == NULL)
        loging.logfile = fopen(loging.filepath, "a+");
    if (loging.logfile == NULL)
    {
        printf("Open Log File Fail!");
        return LOG_FILE_OPEN_FAIL;
    }
    //写入日志级别，日志时间
    fprintf(loging.logfile, "[%s] [%s]", loging.logtime, LogLevelText[loglevel - 1]);
    return OPERATION_OK;
}

/*
 *日志写入
 * */
int log_write(unsigned char loglevel, char *format, ...)
{
    //[为支持多线程需要加锁] pthread_mutex_lock(&mutex_log); //lock.

    //初始化日志
    if (initlog(loglevel) != OPERATION_OK)
    {
        printf("open log file fail!\n");
        return LOG_FILE_OPEN_FAIL;
    }
    //打印日志信息
    va_list args;
    va_start(args, format);
    vfprintf(loging.logfile, format, args);
    va_end(args);
    //文件刷出
    fflush(loging.logfile);
    //日志关闭
    if (loging.logfile != NULL)
        fclose(loging.logfile);
    loging.logfile = NULL;

    //[为支持多线程需要加锁] pthread_mutex_unlock(&mutex_log); //unlock.
    return OPERATION_OK;
}