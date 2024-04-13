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

#define READ_BUFFER_SIZE 1000
#define MAX_IP_ADDRESSES 100

uint ip_to_int(char *ip) {
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

char* int_to_ip(uint32_t ip_int) {
    static char ip_str[16];
    sprintf(ip_str, "%u.%u.%u.%u",
        (ip_int >> 24) & 0xFF,
        (ip_int >> 16) & 0xFF,
        (ip_int >> 8) & 0xFF,
        ip_int & 0xFF);
    return ip_str;
}


volatile int num_ip_addresses = 0;
volatile uint* ip_addresses[MAX_IP_ADDRESSES];

static ssize_t sysfs_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
	int total_bytes_written = 0;
	for (int i = 0; i < num_ip_addresses; i++) {
    	int written = sprintf((buf + total_bytes_written), "%u\n", ip_addresses[i]);
		total_bytes_written += written;
	}
	return total_bytes_written;
}

void delete_ip_address(uint ip_address) {
	for (int i = 0; i < num_ip_addresses; i++) {
		if (ip_addresses[i] == ip_address) {
			ip_addresses[i] = ip_addresses[num_ip_addresses - 1];	
			num_ip_addresses--;
			break;
		}
	}
}

static ssize_t sysfs_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
	// Check for deletion
	char c = '0';
	sscanf(buf, "%c", &c);
	if (c == 'D') {
		buf++;
		uint to_delete;
		sscanf(buf, "%u", &to_delete);
		delete_ip_address(to_delete);
		return count;
	}

	// Otherwise append ip addresses
	int added = 0;
	for (int i = num_ip_addresses; i < MAX_IP_ADDRESSES && sscanf(buf, "%u", &ip_addresses[i]) == 1; i++) {
		while (*buf != '\n' && *buf != '\0') buf++;
		if (*buf == '\n') buf++;
		added++;
	}
	num_ip_addresses += added;

	return count;
}

static struct kobject *kobj_ref;
static struct attribute_group* ag;
static struct kobj_attribute a1 = __ATTR(ip_addresses, 0664, sysfs_show, sysfs_store);
static struct attribute* attribute_array[] = {&a1.attr, NULL};

void init_config(void) {
	ag = kmalloc(sizeof (struct attribute_group), GFP_KERNEL);
	ag->name = "group";
	ag->attrs = attribute_array;
	kobj_ref = kobject_create_and_add("firewall_config", kernel_kobj);	

	if(sysfs_create_group(kobj_ref, ag)) {
    	printk(KERN_INFO"Cannot create sysfs group...");
		return;
	} else {
		pr_info("Successfully created sysfs group.....\n");
	}
}

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	unsigned int source_ip_address = ntohl(iph->addrs.saddr);

	bool should_drop = false;
	for (int i = 0; i < num_ip_addresses; i++) {
		if (source_ip_address == ip_addresses[i]) {
			should_drop = true;
			break;
		}
	}

	if (should_drop) {
		// pr_info("DROPPED A PACKET FROM IP ADDRESS %s\n", int_to_ip(source_ip_address));
		return NF_DROP;
	}
	
	return NF_ACCEPT;
}

static int __init LKM_init(void)
{
	init_config();
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
	pr_info("Unregistering net hook");
	nf_unregister_net_hook(&init_net, nfho);
	pr_info("Freeing nfho");
	kfree(nfho);
	pr_info("Freeing config");
	kfree(ag);
	pr_info("Freeing kobj_ref");
	kobject_put(kobj_ref);
}

module_init(LKM_init);
module_exit(LKM_exit);

MODULE_LICENSE("GPL");