#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
 #include <ctype.h>

#define C_DEV_PATH "/dev/network_firewall_device"
#define NUM_OF_ARGS 8

#define NETWORK_IN_TYPE '0'
#define NETWORK_OUT_TYPE '1'
#define REMOVE_ACTION '0'
#define ADD_ACTIONE '1'
#define IPS_ACTION '0'
#define PORTS_ACTION '1'

#define NETWORK_TYPE_COMMAND "-n"
#define ACTION_TYPE_COMMAND "-a"
#define COMMAND_TYPE "-t"

int print_help_statement(){
    printf("Please use -h or --help for more information\n");
    return 0;
}

int display_help(){
    printf("The commands are: \n");
    printf("\t -n \t The type of the network you would like to filter (IN or OUT)\n");
    printf("\t -t \t The type of the element you would like to filter (PORT or IP)\n");
    printf("\t -a \t The type of the action you would like to perform (ADD or REMOVE)\n");
    printf("\t -h \t help information\n");
    printf("Example for using: \n");
    printf("\t firewallctl -n IN -a ADD -t IP 127.0.0.1\n");
    return 0;
}

int display_info(int fd){
    char read_buff[9999];

    read(fd, read_buff, 9999);
    printf("%s\n", read_buff);
    close(fd);
    return 0;
}

int not_valid_command(const char* cmd){
    printf("%s is not valid command - ", cmd);
    return print_help_statement();
}

int test_argument(const char** argv){
    int is_valid = 1;
    if(strcmp(argv[1], NETWORK_TYPE_COMMAND) != 0 && 
       strcmp(argv[3], NETWORK_TYPE_COMMAND) != 0 &&
       strcmp(argv[5], NETWORK_TYPE_COMMAND) != 0){
        printf("Missing %s command\n", NETWORK_TYPE_COMMAND);
        is_valid = 0;
    }

    if(strcmp(argv[1], ACTION_TYPE_COMMAND) != 0 && 
       strcmp(argv[3], ACTION_TYPE_COMMAND) != 0 &&
       strcmp(argv[5], ACTION_TYPE_COMMAND) != 0){
        printf("Missing %s command\n", ACTION_TYPE_COMMAND);
        is_valid = 0;
    }

    if(strcmp(argv[1], COMMAND_TYPE) != 0 && 
       strcmp(argv[3], COMMAND_TYPE) != 0 &&
       strcmp(argv[5], COMMAND_TYPE) != 0){
        printf("Missing %s command\n", COMMAND_TYPE);
        is_valid = 0;
    }

    return is_valid;
}

int is_number(const char* str){
    int index = 0;
    int len = strlen(str);
    for(index = 0;index < len && isdigit(str[index]);index++);
    
    return index == len;
}

int is_ip_v4(const char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main(const int argc, const char** argv){

    int fd = open(C_DEV_PATH, O_RDWR);

    char network_type;
    char action_type;
    char ips_or_ports;
    int network_type_index = 0;
    int action_type_index = 0;
    int ips_or_ports_index = 0;

    if(argc < 2)
        return print_help_statement();

    if(argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
        return display_help();
    else if(argc == 2 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--info") == 0))
        return display_info(fd);
    else if(argc != NUM_OF_ARGS)
        return not_valid_command(argv[1]);
    else if(test_argument(argv) == 0)
        return print_help_statement();        

    if(strcmp(argv[1], NETWORK_TYPE_COMMAND) == 0)
        network_type_index = 2;
    else if(strcmp(argv[1], ACTION_TYPE_COMMAND) == 0)
        action_type_index = 2;
    else
        ips_or_ports_index = 2;

    if(strcmp(argv[3], NETWORK_TYPE_COMMAND) == 0)
        network_type_index = 4;
    else if(strcmp(argv[3], ACTION_TYPE_COMMAND) == 0)
        action_type_index = 4;
    else
        ips_or_ports_index = 4;

    if(strcmp(argv[5], NETWORK_TYPE_COMMAND) == 0)
        network_type_index = 6;
    else if(strcmp(argv[5], ACTION_TYPE_COMMAND) == 0)
        action_type_index = 6;
    else
        ips_or_ports_index = 6;

    if(strcmp(argv[network_type_index], "IN") == 0 || strcmp(argv[network_type_index], "in") == 0)
        network_type = NETWORK_IN_TYPE;
    else if(strcmp(argv[network_type_index], "OUT") == 0 || strcmp(argv[network_type_index], "out") == 0)
        network_type = NETWORK_OUT_TYPE;
    else
        return not_valid_command(argv[network_type_index]);

    if(strcmp(argv[action_type_index], "ADD") == 0 || strcmp(argv[action_type_index], "add") == 0)
        action_type = ADD_ACTIONE;
    else if(strcmp(argv[action_type_index], "REMOVE") == 0 || strcmp(argv[action_type_index], "remove") == 0)
        action_type = REMOVE_ACTION;
    else
        return not_valid_command(argv[action_type_index]);

    if(strcmp(argv[ips_or_ports_index], "IP") == 0 || strcmp(argv[ips_or_ports_index], "ip") == 0)
        ips_or_ports = IPS_ACTION;
    else if(strcmp(argv[ips_or_ports_index], "PORT") == 0 || strcmp(argv[ips_or_ports_index], "port") == 0)
        ips_or_ports = PORTS_ACTION;
    else
        return not_valid_command(argv[ips_or_ports_index]);

    if(ips_or_ports == PORTS_ACTION && !is_number(argv[7])){
        printf("%s is not valid PORT\n", argv[7]);
        return not_valid_command(argv[7]);
    }
    else if(ips_or_ports == IPS_ACTION && !is_ip_v4(argv[7])){
            printf("%s is not valid IP\n", argv[7]);
            return not_valid_command(argv[7]);
    }

    char buffer[256];
    buffer[0] = network_type;
    buffer[1] = action_type;
    buffer[2] = ips_or_ports;
    buffer[3] = '\0';
    strcat(buffer, argv[7]);


    int len = write(fd, buffer, strlen(buffer));
    close(fd);

    if(len < strlen(buffer)){
        printf("Your command %s did not executed.\n", buffer);
        return 0;
    }

    printf("Your command %s executed successfully there is not need to restart the process.\n", buffer);
    return 0;
}
