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

unsigned int ip_to_int(const char *ip) {
    unsigned int result = 0;
    unsigned int part = 0;
    while (*ip) {
        if (*ip == '.') {
            result = (result << 8) + part;
            part = 0;
        } else {
            part = part * 10 + (*ip - '0');
        }
        ip++;
    }
    result = (result << 8) + part;

    return result;
}

struct ip_address_node {
	struct list_head list;
	int ip_address;
};

struct firewall_config {
	struct list_head ip_address_list_head;
};

static struct firewall_config* config = NULL;

void init_config(void) {
	config = kmalloc(sizeof(struct firewall_config), GFP_KERNEL);
	INIT_LIST_HEAD(&config->ip_address_list_head);
}

void add_ip_address_to_config(int ip_address) {
	struct ip_address_node* new_node = kmalloc(sizeof(struct ip_address_node), GFP_KERNEL);
	if (!new_node) {
		pr_err("Could not allocate memory for new ip address node\n");
		return;
	}
	new_node->ip_address = ip_address;
	list_add(&new_node->list, &config->ip_address_list_head);
}

bool load_config(void) {
    const char* config_file_name = "/.firewallconfig";
    struct file* file = filp_open("/.firewallconfig", O_RDONLY, 0);
    if (IS_ERR(file)) {
        pr_err("%d\n", PTR_ERR(file));
        return false;
    }
    else {
        char buf[100];
        kernel_read(file, buf, 100, NULL);
        pr_info("%s\n", buf);
        return true;
    }
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

	struct list_head* cur = NULL;
	list_for_each(cur, &config->ip_address_list_head) {
		struct ip_address_node* node = list_entry(cur, struct ip_address_node, list);
	}
	
	// if (source_ip_address == ip_to_int(blocked_ip_address)) {
	// 	pr_info("DROPPED A PACKET FROM IP ADDRESS %s\n", blocked_ip_address);
	// 	pkt_hex_dump(skb);
	// 	return NF_DROP;
	// }

    // pr_info("I'm here!\n");

	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
        if (udph->dest != 43426) {
            // pr_info("Received UDP packet destined for port %d\n", udph->dest);
        }
		if (ntohs(udph->dest) == 53) {
            // pr_info("Received DNS packet with contents\n");
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
	init_config();
    load_config();
	struct firewall_config* config = init_config();
	add_ip_address_to_config(config, 10);
	add_ip_address_to_config(config, 11);
	add_ip_address_to_config(config, 12);
	add_ip_address_to_config(config, 13);
	add_ip_address_to_config(config, 14);
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