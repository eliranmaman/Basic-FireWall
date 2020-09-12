/*
    Module name: Network Load Balancer.
    By: Eliran Maman
    Course: Linux - Kernel developer.
    4.1.0 <= Kernel Version < 4.4.0 
    License: GPL

    This module hook on the pre-routing protocol in the stack (Using Netfilter)
    Source: https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html
*/

#define NUM_OF_SERVERS 1

#include <linux/module.h>
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/ip.h>             
#include <linux/kernel.h> 
#include <linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h> 

/* Register params 
module_param(protocol_type, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(protocol_type, "An integer, representing the protocol types as a bit map (e.g TCP is 6 so 00100000=32");
*/



static struct nf_hook_ops netfops;                    
static const char* servers[NUM_OF_SERVERS] = {
    "3.86.181.148",
    "54.89.147.166",
};
static int iterator = 0;

const char* choose_server(void){
    /* We implement a simple round robin algorithm => this is in separate function for robustic reasons. */
    iterator = ++iterator%NUM_OF_SERVERS;
    return servers[iterator];
}

int check_destionation(const __be32	saddr){
    int index;
    for(index=0;index<NUM_OF_SERVERS;index++)
        if(in_aton(servers[index]) == saddr)
            return false;
    return true;
}



unsigned int main_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct nf_hook_state *state){

    struct iphdr *iph;
    iph = ip_hdr(skb); //Get the IP information

    
    struct tcphdr *tcp_header;    
    unsigned int sport , dport;

    tcp_header= (struct tcphdr *)((__u32 *)iph+ iph->ihl); 
    sport = htons((unsigned short int) tcp_header->source);
    dport = htons((unsigned short int) tcp_header->dest);  



    if(check_destionation(iph->saddr) && dport == 80){
        int offset, tcplen;
        struct tcphdr *tcph;
        const char* chosen_server = choose_server();
        printk(KERN_INFO " *********************** \n");
        printk(KERN_INFO "Packet arrive From: %pI4:%d ==> %pI4:%d\n", &iph->saddr, sport, &iph->daddr, dport);
        printk(KERN_INFO "The choosen server is: (%d) %s\n", iterator, chosen_server);
        iph->daddr = in_aton(chosen_server); //Choose the new server to forward the request.
        tcph = (struct tcphdr *)(skb->data + iph->ihl * 4);
        tcplen = (skb->len - (iph->ihl << 2));
        tcph->check = 0; 
        tcph->check = tcp_v4_check(tcplen, 
            iph->saddr, 
            iph->daddr, 
            csum_partial((char *)tcph, tcplen, 0)); 
        skb->ip_summed = CHECKSUM_NONE; //stop offloading
        iph->check = 0;
        iph->check = ip_fast_csum((u8 *)iph, iph->ihl);         


        printk(KERN_INFO "Forward the request from: %pI4 to: %pI4\n", &iph->saddr, &iph->daddr);
        printk(KERN_INFO "Return NF_INET_FORWARD\n");
        return NF_INET_LOCAL_OUT;
    }

accept:
    return NF_ACCEPT;
}

void register_module_hooks(void){
    netfops.hook              =       (void*)main_hook;
    netfops.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
    netfops.pf = PF_INET;                           //IPV4 packets
    netfops.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
    nf_register_net_hook(&init_net, &netfops);
}

void unregister_module_hooks(void){
    nf_unregister_net_hook(&init_net, &netfops); 
}
 
 
int __init entry_point(void)
{
    /*
    This is the entry point for the module.
    */
    printk(KERN_INFO "Initialize the Network Load Balancer Module.\n");
    register_module_hooks();
    return 0;
}
 
void  exit_point(void) 
{ 
    /*
        This is the exit point for the module
    */
    printk(KERN_INFO "Shuting down the Network Load Balancer Module.\n");
    unregister_module_hooks();
}
 
module_init(entry_point);
module_exit(exit_point);
MODULE_LICENSE("GPL");