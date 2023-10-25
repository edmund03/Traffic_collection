#ifndef __ERROR_H
#define __ERROR_H

#define OPERATION_OK 0

/*
 * config errors
 */
#define ERROR_CONFIG_FILE_NOT_EXISTS 1

/*
 * alloc errors
 */
#define ERROR_ALLOC_FAILURE 1

/*
* initial error
*/
#define ERROR_DEFAULT_CONFIG_LOAD_FAIL 1
#define ERROR_PCAP_INTREFACE_CREATE_FAIL 2

/*
* params
*/
#define HINT_HELP_INFO 1

/*
* log
*/
#define LOG_FILE_OPEN_FAIL 1
#define LOG_FILE_PATH_ERROR 2
#define LOG_FILE_PATH_CREATE_ERROR 3

/**
 * pcap folder
*/
#define PCAP_FOLDER_MKDIR_FAIL 1

#endif