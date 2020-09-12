
/* 

Netfilter hook
NF_PRE_ROUTING => pre routing (ip recive finish)
NF_INET_FORWARD => ..
NF_INET_POST_ROUTING => ..

Hook Registertion => nf_register_hook(s)(....) 
static struct nf_hook_ops
Responses for hooks - 
NF_ACCEPT => it's ok.
NF_DROP => DROP
NF_STOLEN => I'll take over this packet.
NF_REPEAT => Invoke me again
NF_QUEUE => Q it (take the packet and put it in the queue that take it to the user.) 
*/ 

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;         //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); //you can access to IP source and dest - ip_header->saddr, ip_header->daddr
  struct tcphdr *tcp_header;
  
  if (ip_header->protocol == 6) //TCP protocol
  {
    printk(KERN_INFO "TCP Packet\n");
    tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); //Note: +20 is only for incoming packets
    printk(KERN_INFO "Source Port: %u\n", tcp_header->source); //can access dest in the same way
  }
  return NF_ACCEPT;                                                                   //accept the packet
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook

  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);                     //cleanup – unregister hook
} 