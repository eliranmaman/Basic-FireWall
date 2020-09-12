#include <linux/module.h>
#include <linux/skbuff.h>          
#include <linux/init.h>
#include <net/sock.h>
#include <linux/inet.h>
#include <linux/ip.h>             
#include <linux/kernel.h> 
#include <linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h> 
 
 
unsigned int main_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    
    printk(KERN_INFO "Packet arrive to the system.\n");

    
    iph = ip_hdr(skb);
    if(iph->saddr == in_aton("127.0.0.1"))
    { 
        printk("Droped the packet..");
        return NF_DROP; 
    }
    return NF_ACCEPT;
}
 
static struct nf_hook_ops netfops;                    
 
int __init my_module_init(void)
{
    netfops.hook              =       (void*)main_hook;
    netfops.pf                =       PF_INET;        
    netfops.hooknum           =       0;
    netfops.priority          =       NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &netfops);
 
    return 0;
}
 
void  my_module_exit(void) 
{ 
    nf_unregister_net_hook(&init_net, &netfops); 
}
 
module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");