#ifndef __UTIL_H
#define __UTIL_H

#include "stdio.h"
#include "stdbool.h"
#include "stddef.h"
#include "ctype.h"
#include "string.h"
#include "unistd.h"

#define MAXFILEPATH (512)
#define MAXFILENAME (50)

/**
 * string
*/
bool strIsEmpty(char *str);
char* Int2String(int num,char *str);

/**
* file
*/
bool check_file_exist(char *filepath);
int mkdir_folder(char *path);

/**
 * dump
*/
void dump_pkt(char *packet, int len);

/**
* time
*/


#endif