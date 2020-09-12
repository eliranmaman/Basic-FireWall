#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(){
    char read_buff[9999];
    int fd = open("/dev/network_firewall_device",O_RDWR);

    read(fd, read_buff, 9999);
    printf("%s\n", read_buff);
}