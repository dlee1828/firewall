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

#define CONFIG_FILE_PATH "/.firewallconfig"
#define READ_BUFFER_SIZE 1000

unsigned int ip_to_int(char *ip) {
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

#define MAX_IP_ADDRESSES 100

volatile int* ip_addresses[MAX_IP_ADDRESSES] = {0};

static ssize_t sysfs_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
	int total_bytes_written = 0;
	for (int i = 0; i < MAX_IP_ADDRESSES && ip_addresses[i] != 0; i++) {
    	int written = sprintf((buf + total_bytes_written), "%d\n", ip_addresses[i]);
		total_bytes_written += written;
	}
	return total_bytes_written;
}

static ssize_t sysfs_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
	int index = 0;
	while(index < MAX_IP_ADDRESSES && sscanf(buf, "%d", &ip_addresses[index]) == 1) {
		while (*buf != '\n' && *buf != '\0') buf++;
		if (*buf == '\n') buf++;
		index++;
	}

	return count;
}

static struct kobject *kobj_ref;
static struct attribute_group* ag;
static struct kobj_attribute a1 = __ATTR(ip_addresses, 0664, sysfs_show, sysfs_store);
static struct attribute* attribute_array[] = {&a1.attr, NULL};

void reload_config(void) {
	ag = kmalloc(sizeof (struct attribute_group), GFP_KERNEL);
	ag->name = "group";
	ag->attrs = attribute_array;
	kobj_ref = kobject_create_and_add("firewall-config", kernel_kobj);	

	if(sysfs_create_group(kobj_ref, ag)) {
    	printk(KERN_INFO"Cannot create sysfs group...");
		return;
	} else {
		pr_info("Successfully created sysfs group.....\n");
	}

	return;

    // const char* config_file_name = CONFIG_FILE_PATH;
    // struct file* file = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
    // if (IS_ERR(file)) {
	// 	pr_warn("Couldn't open config file\n");
    // 	pr_warn("%d\n", PTR_ERR(file));
    // }
    // else {
	// 	pr_info("Successfully opened file");
    //     char buf[READ_BUFFER_SIZE];
    //     kernel_read(file, buf, READ_BUFFER_SIZE, NULL);

	// 	char ip_address_line[16];
	// 	int line_index = 0;
	// 	for (int i = 0; i < READ_BUFFER_SIZE; i++) {
	// 		if (buf[i] == '\0') break;
	// 		else if (buf[i] == '\n') {
	// 			ip_address_line[line_index] = "\0";
	// 			add_ip_address_to_config(ip_to_int(ip_address_line));
	// 			line_index = 0;
	// 		}
	// 		else {
	// 			ip_address_line[line_index] = buf[i];
	// 			line_index++;
	// 		}
	// 	}

	// 	filp_close(file, NULL);
    // }
}

static struct nf_hook_ops *nfho = NULL;

static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_ACCEPT;

	// bool config_loaded = reload_config();
	// if (!config_loaded) {
	// 	return NF_ACCEPT;
	// }	

	skb->head;
	struct iphdr *iph;
	struct udphdr *udph;
	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	unsigned int source_ip_address = ntohl(iph->addrs.saddr);

	const char* target = "142.250.114.113";

	bool ping = false;
	if (source_ip_address == ip_to_int(target)) {
		pr_info("Received packet from ping, source is %d, target is %d\n", source_ip_address, ip_to_int(target));
		ping = true;
	}

	bool should_drop = false;
	if (should_drop) {
		pr_info("DROPPED A PACKET FROM IP ADDRESS %s\n", source_ip_address);
		return NF_DROP;
	}

	// if (iph->protocol == IPPROTO_UDP) {
	// 	udph = udp_hdr(skb);
    //     if (udph->dest != 43426) {
    //         // pr_info("Received UDP packet destined for port %d\n", udph->dest);
    //     }
	// 	if (ntohs(udph->dest) == 53) {
    //         // pr_info("Received DNS packet with contents\n");
	// 		return NF_ACCEPT;
	// 	}
	// }
	// else if (iph->protocol == IPPROTO_TCP) {
	// 	return NF_ACCEPT;
	// }
	
	return NF_ACCEPT;
}

static struct proc_dir_entry *proc_file; 
static const struct proc_ops proc_file_fops = { 
}; 

static int __init LKM_init(void)
{
	reload_config();
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