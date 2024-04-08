#ifndef FIREWALL_UTIL_H
#define FIREWALL_UTIL_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

bool read_config(void) {
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

void pkt_hex_dump(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch; 

    printk("Packet hex dump:\n");
    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t) ch);
        }

        data += linelen;
        li += 10; 

        printk(KERN_CONT "\n");
    }
}

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
    result = (result << 8) + part; // For the last part after the last dot

    return result;
}

#endif