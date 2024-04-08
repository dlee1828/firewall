/*****************************************************
 * This code was compiled and tested on Ubuntu 18.04.1
 * with kernel version 4.15.0
 *****************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h> 
#include <linux/list.h>
#include "firewall_util.h"

struct ip_address_node {
	struct list_head list;
	int ip_address;
};

struct firewall_config {
	struct list_head ip_address_list_head;
};

void add_ip_address(struct firewall_config* config, int ip_address) {
	pr_info("about to run struct ip_address_node* new_node = kmalloc(sizeof(struct ip_address_node), GFP_KERNEL);");
	struct ip_address_node* new_node = kmalloc(sizeof(struct ip_address_node), GFP_KERNEL);
	if (!new_node) {
		return;
	}
	pr_info("about to run new_node->ip_address = ip_address;");
	new_node->ip_address = ip_address;
	INIT_LIST_HEAD(&new_node->list);
	pr_info("about to run 	list_add(&config->ip_address_list_head, &new_node->list);");
	pr_info("&config->ip_address_list_head = %d, &new_node->list = %d", &config->ip_address_list_head,  &new_node->list);
	list_add(&config->ip_address_list_head, &new_node->list);
}

void print_ip_addresses(struct firewall_config* config) {
	// TODO
}

struct firewall_config* init_config(void) {
	struct firewall_config* config = kmalloc(sizeof(struct firewall_config), GFP_KERNEL);
	INIT_LIST_HEAD(&config->ip_address_list_head);
	return config;
}

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	skb->head;
	struct iphdr *iph;
	struct udphdr *udph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	const char* blocked_ip_address = "17.253.144.10";

	int source_ip_address = ntohl(iph->addrs.saddr);
	
	// if (source_ip_address == ip_to_int(blocked_ip_address)) {
	// 	pr_info("DROPPED A PACKET FROM IP ADDRESS %s\n", blocked_ip_address);
	// 	pkt_hex_dump(skb);
	// 	return NF_DROP;
	// }

    // pr_info("I'm here!\n");

	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
        if (udph->dest != 43426) {
            pr_info("Received UDP packet destined for port %d\n", udph->dest);
        }
		if (ntohs(udph->dest) == 53) {
            pr_info("Received DNS packet with contents\n");
			return NF_ACCEPT;
		}
	}
	else if (iph->protocol == IPPROTO_TCP) {
		return NF_ACCEPT;
	}
	
	return NF_ACCEPT;
}

static struct proc_dir_entry *proc_file; 
static const struct proc_ops proc_file_fops = { 
}; 

static int __init LKM_init(void)
{
    read_config();
	struct firewall_config* config = init_config();
	add_ip_address(config, 10);
	add_ip_address(config, 11);
	add_ip_address(config, 12);
	print_ip_addresses(config);
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);

    return 0;
}

static void __exit LKM_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(LKM_init);
module_exit(LKM_exit);

MODULE_LICENSE("GPL");