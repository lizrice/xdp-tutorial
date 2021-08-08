#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_lb_kern.h"

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))
#define CLIENT_IP_ADDRESS IP_ADDRESS(CLIENT)
#define LB_IP_ADDRESS IP_ADDRESS(LB)
#define BE_A_IP_ADDRESS IP_ADDRESS(BACKEND_A)
#define BE_B_IP_ADDRESS IP_ADDRESS(BACKEND_B)

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    int action = XDP_PASS;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        goto out;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        goto out;

    if (iph->saddr == CLIENT_IP_ADDRESS)
    {
        char be = BACKEND_A;
        if (bpf_ktime_get_ns() % 2)
            be = BACKEND_B;
        bpf_printk("Forward to backend %d", be);

        iph->daddr = IP_ADDRESS(be);
        eth->h_dest[5] = be;
    }
    else
    {
        bpf_printk("Reply to client");
        iph->daddr = CLIENT_IP_ADDRESS;
        eth->h_dest[5] = CLIENT;
    }

    iph->saddr = LB_IP_ADDRESS;
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);
    action = XDP_TX;

out:
    return action;
}

// SEC("xdp_lb")
// int xdp_load_balancer(struct xdp_md *ctx)
// {
//     int action = XDP_PASS;

//     bpf_printk("Hello");

//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     struct ethhdr *eth = data;
//     if (data + sizeof(*eth) > data_end)
//         return XDP_ABORTED;

//     if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
//         goto out;

//     struct iphdr *iph = data + sizeof(*eth);
//     if (data + sizeof(*eth) + sizeof(*iph) > data_end)
//         return XDP_ABORTED;

//     if (iph->protocol != IPPROTO_TCP)
//         goto out;

//     if (iph->saddr == CLIENT_IP_ADDRESS)
//     {
//         bpf_printk("Forward to backend");

//         if (bpf_ktime_get_ns() % 2)
//         {
//             iph->daddr = BE_A_IP_ADDRESS;
//             eth->h_dest[5] = BACKEND_A;
//         }
//         else
//         {
//             iph->daddr = BE_B_IP_ADDRESS;
//             eth->h_dest[5] = BACKEND_B;
//         }
//     }
//     else
//     {
//         bpf_printk("Return to client");
//         iph->daddr = CLIENT_IP_ADDRESS;
//         eth->h_dest[5] = CLIENT;
//     }
//     iph->saddr = LB_IP_ADDRESS;
//     eth->h_source[5] = LB;

//     iph->check = iph_csum(iph);
//     action = XDP_TX;

// out:
//     return action;
// }

char _license[] SEC("license") = "GPL";
