#include "sys/stat.h"
#include "sys/types.h"

#include "util.h"
#include "error.h"
#include "log.h"

/**
 * string
 */
bool strIsEmpty(char *str)
{
    return (str == NULL || str[0] == '\0');
}

char* Int2String(int num,char *str)//10进制 
{
    int i = 0;//指示填充str 
    if(num<0)//如果num为负数，将num变正 
    {
        num = -num;
        str[i++] = '-';
    } 
    //转换 
    do
    {
        str[i++] = num%10+48;//取num最低位 字符0~9的ASCII码是48~57；简单来说数字0+48=48，ASCII码对应字符'0' 
        num /= 10;//去掉最低位    
    }while(num);//num不为0继续循环
    
    str[i] = '\0';
    
    //确定开始调整的位置 
    int j = 0;
    if(str[0]=='-')//如果有负号，负号不用调整 
    {
        j = 1;//从第二位开始调整 
        ++i;//由于有负号，所以交换的对称轴也要后移1位 
    }
    //对称交换 
    for(;j<i/2;j++)
    {
        //对称交换两端的值 其实就是省下中间变量交换a+b的值：a=a+b;b=a-b;a=a-b; 
        str[j] = str[j] + str[i-1-j];
        str[i-1-j] = str[j] - str[i-1-j];
        str[j] = str[j] - str[i-1-j];
    } 
    
    return str;//返回转换后的值 
}

/**
 * file
 */
bool check_file_exist(char *filepath)
{
    if (access(filepath, F_OK) == 0)
        return true;
    return false;
}
int mkdir_folder(char *path)
{
    if (strIsEmpty(path) || path[0] != '/')
        return PCAP_FOLDER_MKDIR_FAIL;
    char current[MAXFILEPATH] = {0}, folder_path[MAXFILEPATH] = {0};
    int offset = 1;
    while (1)
    {
        sscanf(path + offset, "%[^/]", current);
        if (strIsEmpty(current))
            break;
        memcpy(folder_path + strlen(folder_path), "/", 1);
        memcpy(folder_path + strlen(folder_path), current, strlen(current));
        if ((access(folder_path, F_OK) != 0) && (mkdir(folder_path, 0777) != 0))
        {
            return PCAP_FOLDER_MKDIR_FAIL;
        }
        if (strcmp(folder_path, path) == 0)
            break;
        offset += strlen(current) + 1;
    }
    return OPERATION_OK;
}

/**
 * dump
 */
void dump_pkt(char *packet, int len)
{
    int i = 0;

    if (!packet || len <= 0)
        return;
    for (i = 0; i < len; i++)
    {
        if (0 == i % 16)
        {
            printf("\t");
        }
        if (0 == i % 2)
        {
            printf(" ");
        }

        printf("%02x", *(packet + i));

        if (15 == i % 16)
        {
            printf("\n");
        }
    }
    printf("\n");
    return;
}
