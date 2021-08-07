/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct server
{
    unsigned char mac[ETH_ALEN];
};

// Map will be indexed by the IP address and return the Ethernet address
struct bpf_map_def SEC("maps") backends = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(unsigned int),
    .value_size = ETH_ALEN,
    .max_entries = 1,
};

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

#define HOST_IP_ADDRESS (unsigned int)((172) + (17 << 8) + (0 << 16) + (1 << 24))
#define BE_IP_ADDRESS (unsigned int)((172) + (17 << 8) + (0 << 16) + (2 << 24))
#define LB_IP_ADDRESS (unsigned int)((172) + (17 << 8) + (0 << 16) + (4 << 24))

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *iph;

    int action = XDP_PASS;

    bpf_printk("Got a packet");

    // Packet starts with the ethernet header
    eth = data;
    if (eth + 1 > data_end)
    {
        return XDP_ABORTED;
    }

    // We are only interested in IP packets
    unsigned short proto = bpf_ntohs(eth->h_proto);
    if (proto != ETH_P_IP)
    {
        bpf_printk("Ethernet proto %d", proto);
        goto out;
    }

    // And then there's an IP header
    iph = data + sizeof(*eth);
    if (iph + 1 > data_end)
    {
        return XDP_ABORTED;
    }

    // We are only interested in TCP/IP
    if (iph->protocol != IPPROTO_TCP)
    {
        bpf_printk("IP proto %d", iph->protocol);
        goto out;
    }

    bpf_printk("Got a TCP packet");

    // If the request comes from the host, redirect to a backend
    if (iph->saddr == HOST_IP_ADDRESS)
    {
        bpf_printk("Redirect to a backend");
        bpf_printk("From %x", iph->saddr);
        bpf_printk("To %x", BE_IP_ADDRESS);
        iph->saddr = LB_IP_ADDRESS;
        iph->daddr = BE_IP_ADDRESS;
        eth->h_dest[5] = 2;
        eth->h_source[5] = 4;

        struct server *s;
        s = bpf_map_lookup_elem(&backends, &iph->saddr);
        if (!s)
        {
            bpf_printk("No server address in map");
        }
        else
        {
            bpf_printk("Server address in map");
        }
    }
    else
    {
        bpf_printk("Redirect to a host");
        iph->daddr = HOST_IP_ADDRESS;
        iph->saddr = LB_IP_ADDRESS;
        eth->h_source[5] = 4;
        eth->h_dest[0] = 0x02;
        eth->h_dest[1] = 0x42;
        eth->h_dest[2] = 0xa1;
        eth->h_dest[3] = 0x70;
        eth->h_dest[4] = 0x8e;
        eth->h_dest[5] = 0xdf;
    }

    iph->check = 0;
    unsigned long long csum =
        bpf_csum_diff(0, 0, (void *)iph, sizeof(*iph), 0);
    iph->check = csum_fold_helper(csum);

    action = XDP_TX;

out:
    return action;
}

char _license[] SEC("license") = "GPL";
