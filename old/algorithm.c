
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