#ifndef __LOG_H
#define __LOG_H
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "time.h"
#include "stdarg.h"
#include "unistd.h"

#define LOG_DEFAULT_PATH "/opt/traffic/log"

#define MAXLEN (2048)
#define MAXFILEPATH (512)
#define MAXFILENAME (50)

#define LOG_SETTING_UNINITIALIZED 0
#define LOG_SETTING_INITIALIZED 1

typedef enum{
	ERROR_1=-1,
	ERROR_2=-2,
	ERROR_3=-3
}ERROR0;
 
 
typedef enum{
	NONE=0,
	INFO=1,
	DEBUG=2,
	WARN=3,
	ERROR=4,
	ALL=255
}LOGLEVEL;
 
typedef struct log{
	char logtime[20];
	char filepath[MAXFILEPATH];
	FILE *logfile;
}LOG;
 
typedef struct logseting{
	int initialized;
	char filepath[MAXFILEPATH];
	// unsigned int maxfilelen;
	// unsigned char loglevel;
}LOGSET;
 
int log_write(unsigned char loglevel,char *fromat,...);

#endif