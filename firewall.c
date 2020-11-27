#include <linux/module.h>
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <linux/tcp.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/uaccess.h> 
#include <linux/inet.h>
#include <linux/ip.h>     
#include <linux/kernel.h> 
#include <linux/netfilter.h>
#include <linux/fs.h>
#include <linux/string.h>

#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>
        
#include <uapi/linux/netfilter_ipv4.h> 
#include <asm/segment.h>
#include <asm/uaccess.h>

/* ------ System Consts ----- */
#define DEVICE_NAME "network_firewall_device"
#define CLASS_NAME "Network_FireWall_Device"
#define NETWORK_IN_TYPE '0'
#define NETWORK_OUT_TYPE '1'
#define REMOVE_ACTION '0'
#define ADD_ACTIONE '1'
#define IPS_ACTION '0'
#define PORTS_ACTION '1'

/* ------ System Data Structures ----- */
typedef struct {
    char** ips;
    int num_of_ips;
    char** ports;
    int num_of_ports;
} Communication_info;

typedef struct {
    Communication_info* in;
    Communication_info* out;
} Sys_data;

/* ------ System Global Vars ----- */
static struct nf_hook_ops netfops_in;     
static struct nf_hook_ops netfops_out;                    
static Sys_data* data;
static int major_num;
static struct class*  dev_class_pointer = NULL; 
static struct device* dev_struct_pointer = NULL; 

static int     c_dev_open(struct inode *, struct file *);
static int     c_dev_close(struct inode *, struct file *);
static ssize_t c_dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t c_dev_write(struct file *, const char *, size_t, loff_t *);
int check_array(char** array, const int len_of_array, const char* target);
int check_port(int port, char n_type);
int check_ip(const __be32 ip, char n_type);

struct file_operations c_dev_operations = {
    .owner = THIS_MODULE,
    .open = c_dev_open,
    .read = c_dev_read,
    .write = c_dev_write,
    .release = c_dev_close
};

/* ---- deal with character devices ---- */
static int c_dev_open(struct inode *node_p, struct file *file_p){
    printk(KERN_INFO "[FireWall][File Operations][OPEN] The character device opened.\n");
    return 0;
}
 
static ssize_t c_dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    int result = 0;
    int index = 0;
    long long copied = 0;
    long long to_copy = 0;

    //Send the information to the user.
    //Network IN Ports
    printk(KERN_INFO "[FireWall][File Operations][READ] Offset is %llu\n", *offset);
    to_copy = strlen("[NETWORK IN][PORTS][BLOCKED]: ");
    copied += to_copy;
    if(copied < len && *offset < copied){
        *offset += to_copy;
        strcat(buffer, "[NETWORK IN][PORTS][BLOCKED]: ");
    }

    for(index=0;index < data->in->num_of_ports && copied < len;index++){
        to_copy = strlen(data->in->ports[index]);
        copied += to_copy+1;
        if(copied < len && *offset < copied){
            *offset += to_copy;
            strcat(buffer, data->in->ports[index]);
            strcat(buffer, " ");
        }
    }

    //Network IN ips
    to_copy = strlen("\n[NETWORK IN][IP][BLOCKED]: ");
    copied += to_copy;
    if(copied < len && *offset < copied){
        *offset += to_copy;
        strcat(buffer, "\n[NETWORK IN][IP][BLOCKED]: ");
    }

    for(index=0;index < data->in->num_of_ips && copied < len;index++){
        to_copy = strlen(data->in->ips[index]);
        copied += to_copy+1;
        if(copied < len && *offset < copied){
            *offset += to_copy;
            strcat(buffer, data->in->ips[index]);
            strcat(buffer, " ");
        }
    }

    //Network out Ports
    to_copy = strlen("\n[NETWORK OUT][PORTS][BLOCKED]: ");
    copied += to_copy;
    if(copied < len && *offset < copied){
        *offset += to_copy;
        strcat(buffer, "\n[NETWORK OUT][PORTS][BLOCKED]: ");
    }

    for(index=0;index < data->out->num_of_ports && copied < len;index++){
        to_copy = strlen(data->out->ports[index]);
        copied += to_copy+1;
        if(copied < len && *offset < copied){
            *offset += to_copy;
            strcat(buffer, data->out->ports[index]);
            strcat(buffer, " ");
        }
    }

    //Network out Ips
    to_copy = strlen("\n[NETWORK OUT][IP][BLOCKED]: ");
    copied += to_copy;
    if(copied < len && *offset < copied){
        *offset += to_copy;
        strcat(buffer, "\n[NETWORK OUT][IP][BLOCKED]: ");
    }

    for(index=0;index<data->out->num_of_ips;index++){
        to_copy = strlen(data->out->ips[index]);
        copied += to_copy+1;
        if(copied < len && *offset < copied){
            *offset += to_copy;
            strcat(buffer, data->out->ips[index]);
            strcat(buffer, " ");
        }
    }
    copied += 1;
    if(copied < len && *offset < copied){
        *offset += 1;
        strcat(buffer, "\n");
    }
    
    result = copy_to_user(buffer, buffer, strlen(buffer));
    if (result != 0){
        printk(KERN_INFO "[FireWall][File Operations][READ] Failed to send %d characters to the user\n", result);
        return -EFAULT;
    }

    printk(KERN_INFO "[FireWall][File Operations][READ] Reading is done.\n");

    result = len > copied ? copied : len;
    return strlen(buffer);
}

char** add_element_to_array(char** array, int len, char* to_add){
    int index = 0;
    char** new_array = kmalloc(sizeof(char*)*(len+1), GFP_KERNEL);
    if(!new_array)
        return NULL;

    for(index=0;index < len;index++)
        new_array[index] = array[index];
    new_array[len] = to_add;

    kfree(array);
    return new_array;

}


char** remove_element_to_array(char** array, int len, char* to_remove){
    int index = 0;
    int iterator = 0;
    char** new_array;

    if(len == 0)
        return NULL;

    new_array = (len-1) > 1 ? kmalloc(sizeof(char*)*(len-1), GFP_KERNEL) : -1;
    for(index=0;index < len;index++){
        if(strncmp(array[iterator], to_remove, strlen(to_remove)) != 0){
            new_array[iterator] = array[iterator];
            iterator++;
        }
    }

    kfree(array);
    return new_array;

}

static ssize_t c_dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    printk(KERN_INFO "[FireWall][File Operations][WRITE] %s Request arrived.\n", buffer);
    char network_type;
    char action_type;
    char ips_or_ports;
    int index = 0;
    char** old_array = NULL;
    int old_len = 0;
    char* element = NULL;
    char** new_array = NULL;
    
    //Check if the request is leggite.
    if(len < 3){
        printk(KERN_INFO "[FireWall][File Operations][WRITE] %s is not leggite request.\n", buffer);
        return len;
    }

    //Extract Params.
    network_type = buffer[0];
    action_type = buffer[1];
    ips_or_ports = buffer[2];


    //Allocate and Copy the element
    element = kmalloc(len-3, GFP_KERNEL);
    if(!element){
        printk(KERN_INFO "[FireWall][File Operations][WRITE] Cannot allocate element space.\n");
        return len;
    }

    for(index=3;index<len;index++)
        element[index-3] = buffer[index];
    element[index-3] = '\0';

    //Network IN + ADD
    if(network_type == NETWORK_IN_TYPE){

        printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_IN Command\n");

        //Check what action we want to achive.
        if(ips_or_ports == IPS_ACTION){
            old_array = data->in->ips;
            old_len = data->in->num_of_ips;
        }else if(ips_or_ports == PORTS_ACTION){
            old_array = data->in->ports;
            old_len = data->in->num_of_ports;
        }else{
            printk(KERN_INFO "[FireWall][File Operations][WRITE] The command is not leggite - cannot recognize IPS or PORTS\n");
            return len;
        }

        if(action_type == ADD_ACTIONE){
            printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_IN + ADD Command\n");


            //check if exist in the array
            if(check_array(old_array, old_len, element) == 1){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] %s is Already exist.\n", element);
                return len;
            }

            //Alocate new array and copy the old array.
            new_array = add_element_to_array(old_array, old_len, element);
            if(new_array == NULL){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] Cannot allocate new array, %s not copied.\n", buffer);
                kfree(element);
                kfree(new_array);
                return len;
            }

            //Update data struct
            if(ips_or_ports == IPS_ACTION){
                data->in->ips = new_array;
                data->in->num_of_ips++;
            }else if(ips_or_ports == PORTS_ACTION){
                data->in->ports = new_array;
                data->in->num_of_ports++;
            }

        }else if(action_type == REMOVE_ACTION){
            printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_IN + REMOVE Command\n");

            //check if exist in the array
            if(check_array(old_array, old_len, element) == 0){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] %s is not exist.\n", element);
                return len;
            }

            new_array = remove_element_to_array(old_array, old_len, element);
            if(new_array == NULL){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] Cannot allocate new array, %s not copied.\n", buffer);
                kfree(element);
                kfree(new_array);
                return len;
            }

            //Update data struct
            if(ips_or_ports == IPS_ACTION){
                data->in->ips = new_array == -1 ? NULL : new_array;
                data->in->num_of_ips = data->in->num_of_ips > 0 ? data->in->num_of_ips-1:0;
            }else if(ips_or_ports == PORTS_ACTION){
                data->in->ports = new_array == -1 ? NULL : new_array;
                data->in->num_of_ports = data->in->num_of_ports > 0 ? data->in->num_of_ports-1:0;
            }

        }else{
            printk(KERN_INFO "[FireWall][File Operations][WRITE] The command is not leggite - cannot recognize ACTION\n");
            return len;
        }
        //Done with network in.
    }else if(network_type == NETWORK_OUT_TYPE){
        printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_OUT Command\n");

        //Check what action we want to achive.
        if(ips_or_ports == IPS_ACTION){
            old_array = data->out->ips;
            old_len = data->out->num_of_ips;
        }else if(ips_or_ports == PORTS_ACTION){
            old_array = data->out->ports;
            old_len = data->out->num_of_ports;
        }else{
            printk(KERN_INFO "[FireWall][File Operations][WRITE] The command is not leggite - cannot recognize IPS or PORTS\n");
            return len;
        }


        if(action_type == ADD_ACTIONE){
            printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_OUT + ADD Command\n");

            //check if exist in the array
            if(check_array(old_array, old_len, element) == 1){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] %s is Already exist.\n", element);
                return len;
            }

            //Alocate new array and copy the old array.
            new_array = add_element_to_array(old_array, old_len, element);
            if(new_array == NULL){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] Cannot allocate new array, %s not copied.\n", buffer);
                kfree(element);
                kfree(new_array);
                return len;
            }

            //Update data struct
            if(ips_or_ports == IPS_ACTION){
                data->out->ips = new_array;
                data->out->num_of_ips++;
            }else if(ips_or_ports == PORTS_ACTION){
                data->out->ports = new_array;
                data->out->num_of_ports++;
            }

        }else if(action_type == REMOVE_ACTION){
            printk(KERN_INFO "[FireWall][File Operations][WRITE] Excecute NETWORK_OUT + REMOVE Command\n");

            //check if exist in the array
            if(check_array(old_array, old_len, element) == 0){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] %s is not exist.\n", element);
                return len;
            }

            new_array = remove_element_to_array(old_array, old_len, element);
            if(new_array == NULL){
                printk(KERN_INFO "[FireWall][File Operations][WRITE] Cannot allocate new array, %s not copied.\n", buffer);
                kfree(element);
                kfree(new_array);
                return len;
            }

            //Update data struct
            if(ips_or_ports == IPS_ACTION){
                data->out->ips = new_array == -1 ? NULL : new_array;
                data->out->num_of_ips = data->out->num_of_ips > 0 ? data->out->num_of_ips-1:0;
            }else if(ips_or_ports == PORTS_ACTION){
                data->out->ports = new_array == -1 ? NULL : new_array;
                data->out->num_of_ports = data->out->num_of_ports > 0 ? data->out->num_of_ports-1:0;
            }

        }else{
            printk(KERN_INFO "[FireWall][File Operations][WRITE] The command is not leggite - cannot recognize ACTION\n");
            return len;
        }
        //Done with network out.
    }else{
        printk(KERN_INFO "[FireWall][File Operations][WRITE] The command is not leggite - cannot recognize NETWORK_TYPE\n");
        return len; 
    }

    printk(KERN_INFO "[FireWall][File Operations][WRITE] %s excecuted successfully.\n", buffer);
    return len;
}


static int c_dev_close(struct inode *inodep, struct file *filep){
    //We are not allocate / opening nothing so we are not relese nothing.
    printk(KERN_INFO "[FireWall][File Operations][READ] Device operetion finished.\n");
    return 0;
}

 

/* ----- Core ------ */
int check_array(char** array, const int len_of_array, const char* target){

    int i = 0;
    for(i=0;i < len_of_array;i++)
        if(strcmp(array[i], target) == 0)
            return 1;    

    return 0;
}

int check_port(int port, char n_type){

    char** array = NULL;
    int len_of_array = 0;

    if(n_type == NETWORK_IN_TYPE){
        array = data->in->ports;
        len_of_array = data->in->num_of_ports;
    }else if(n_type == NETWORK_OUT_TYPE){
        array = data->out->ports;
        len_of_array = data->out->num_of_ports;
    }else{
        return 0;
    }

    char string_port[100];
    sprintf(string_port, "%d\0", port);

    return check_array(array, len_of_array, string_port);
    
}

int check_ip(const __be32 ip, char n_type){

    char** array = NULL;
    int len_of_array = 0;

    if(n_type == NETWORK_IN_TYPE){
        array = data->in->ips;
        len_of_array = data->in->num_of_ips;
    }else if(n_type == NETWORK_OUT_TYPE){
        array = data->out->ips;
        len_of_array = data->out->num_of_ips;
    }else{
        return 0;
    }

    char target[17];
    sprintf(target, "%pI4\0", &ip);


    return check_array(array, len_of_array, target);
    
}


unsigned int network_out(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state){

    //printk(KERN_INFO "[FireWall][NETWORK OUT][INFO] Request arrived");

    struct iphdr *iph;
    struct tcphdr *tcp_header;    
    unsigned int dest_port, source_port;

    iph = ip_hdr(skb); 
    tcp_header= (struct tcphdr *)((__u32 *)iph+ iph->ihl); 
    dest_port = htons((unsigned short int) tcp_header->dest);  
    source_port = htons((unsigned short int) tcp_header->source);  

    //Check port policy.
    if(check_port(dest_port, NETWORK_OUT_TYPE)){
        printk(KERN_INFO "[FireWall][NETWORK OUT][BLOCKED] Packet arrived from: %pI4:%d to  %pI4:%d. Due to Network OUT: Port policy.\n", &iph->saddr, source_port, &iph->daddr, dest_port);
        return NF_DROP;
    }

    //Check ip policy
    if(check_ip(iph->daddr, NETWORK_OUT_TYPE)){
        printk(KERN_INFO "[FireWall][NETWORK OUT][BLOCKED] Packet arrived from: %pI4:%d to  %pI4:%d. Due to Network OUT: IPs policy.\n", &iph->saddr, source_port, &iph->daddr, dest_port);
        return NF_DROP;
    }

    //printk(KERN_INFO "[FireWall][NETWORK OUT][INFO] Request accepted");

    return NF_ACCEPT;
}

unsigned int network_in(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state){

    //printk(KERN_INFO "[FireWall][NETWORK IN][INFO] Request arrived.");

    struct iphdr *iph;
    struct tcphdr *tcp_header;    
    unsigned int dest_port, source_port;

    iph = ip_hdr(skb); 
    tcp_header= (struct tcphdr *)((__u32 *)iph+ iph->ihl); 
    dest_port = htons((unsigned short int) tcp_header->dest);  
    source_port = htons((unsigned short int) tcp_header->source);  

    //Check port policy.
    if(check_port(dest_port, NETWORK_IN_TYPE)){
        printk(KERN_INFO "[FireWall][NETWORK IN][BLOCKED] Packet arrived from: %pI4:%d to  %pI4:%d. Due to Network IN: Port policy.\n", &iph->saddr, source_port, &iph->daddr, dest_port);
        return NF_DROP;
    }

    //Check ip policy
    if(check_ip(iph->saddr, NETWORK_IN_TYPE)){
        printk(KERN_INFO "[FireWall][NETWORK IN][BLOCKED] Packet arrived from: %pI4:%d to  %pI4:%d. Due to Network IN: IPs policy.\n", &iph->saddr, source_port, &iph->daddr, dest_port);
        return NF_DROP;
    }

    //printk(KERN_INFO "[FireWall][NETWORK OUT][INFO] Request accepted");

    return NF_ACCEPT;
}

/* ------ Initial Process -------- */
char* clear_line(char* line){
    if(line[strlen(line)-1] == '\n')
        line[strlen(line)-1] = '\0';
    return line;
}
 
void initial_data(void){

    data = kmalloc(sizeof(Sys_data), GFP_KERNEL);

    data->out = kmalloc(sizeof(Communication_info), GFP_KERNEL);
    data->in = kmalloc(sizeof(Communication_info), GFP_KERNEL);
    
    //Read in->ips
    data->in->num_of_ips = 0;
    data->in->ips = NULL;

    //Read in->ports
    data->in->num_of_ports = 0;
    data->in->ports = NULL;

    //Read out->ips
    data->out->num_of_ips = 0;
    data->out->ips = NULL;

    //Read out->ports
    data->out->num_of_ports = 0;
    data->out->ports = NULL;

    //Register device.
    // Try to dynamically allocate a major number for the device -- more difficult but worth it
    major_num = register_chrdev(0, DEVICE_NAME, &c_dev_operations);
    if (major_num < 0){
        printk(KERN_INFO "[FireWall][Initializing] failed to register a major number.\n");
        return major_num;
    }
    printk(KERN_INFO "[FireWall][Initializing] registered major number successfully: %d\n", major_num);

    // Register the device class
    dev_class_pointer = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(dev_class_pointer)){                // Check for error and clean up if there is
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[FireWall][Initializing] Failed to register device class\n");
        return PTR_ERR(dev_class_pointer);          // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "[FireWall][Initializing] device class registered successfully\n");

    // Register the device driver
    dev_struct_pointer = device_create(dev_class_pointer, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    if (IS_ERR(dev_struct_pointer)){               // Clean up if there is an error
        class_destroy(dev_class_pointer);           // Repeated code but the alternative is goto statements
        unregister_chrdev(major_num, DEVICE_NAME);
        printk(KERN_INFO "[FireWall][Initializing] Failed to create device\n");
        return PTR_ERR(dev_struct_pointer);
    }
    printk(KERN_INFO "[FireWall][Initializing] device created successfully\n");
    
}
 
void register_module_hooks(void){

    //Network in
    netfops_in.hook = (void*)network_in;
    netfops_in.hooknum = NF_INET_PRE_ROUTING;            
    netfops_in.pf = PF_INET;                         
    netfops_in.priority = NF_IP_PRI_FIRST;       

    //Network out
    netfops_out.hook = (void*)network_out;
    netfops_out.hooknum = NF_INET_POST_ROUTING;            
    netfops_out.pf = PF_INET;                         
    netfops_out.priority = NF_IP_PRI_FIRST;          
    nf_register_net_hook(&init_net, &netfops_out);
    nf_register_net_hook(&init_net, &netfops_in);
}
 
int __init entry_point(void)
{
    printk(KERN_INFO "[FireWall][INITIAL] Initial FireWall Module started... \n");
    initial_data();
    printk(KERN_INFO "[FireWall][INITIAL] Initial data completed... \n");
    register_module_hooks();
    printk(KERN_INFO "[FireWall][INITIAL] Register hooks completed... \n");
    return 0;
}
 
/* ------- Terminate Process ----- */
void unregister_module_hooks(void){

    //Remove network in
    nf_unregister_net_hook(&init_net, &netfops_in);
    //Remove network out 
    nf_unregister_net_hook(&init_net, &netfops_out); 

}

void  exit_point(void) 
{ 
    printk(KERN_INFO "[FireWall][EXIT] Initial FireWall Module exit... \n");

    printk(KERN_INFO "[FireWall][EXIT] Unregister hooks... \n");
    unregister_module_hooks();

    printk(KERN_INFO "[FireWall][EXIT] Unregister Character Device... \n");
    device_destroy(dev_class_pointer, MKDEV(major_num, 0)); 
    class_unregister(dev_class_pointer);                  
    class_destroy(dev_class_pointer);           
    unregister_chrdev(major_num, DEVICE_NAME); 

    printk(KERN_INFO "[FireWall][EXIT] Exit function for FireWall Module Completed... \n");
    printk(KERN_INFO "[FireWall][EXIT] C U next time :) \n");

}
 
module_init(entry_point);
module_exit(exit_point);
MODULE_LICENSE("GPL");
