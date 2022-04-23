//go:build ignore
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("socket/probability_half")
int probability_half(struct __sk_buff *skb)
{
        u32 rand = bpf_get_prandom_u32();

        return (rand % 2) == 0;
}

SEC("socket/probability_third")
int probability_third(struct __sk_buff *skb)
{
        u32 rand = bpf_get_prandom_u32();

        return (rand % 3) == 0;
}

SEC("socket/probability_fourth")
int probability_fourth(struct __sk_buff *skb)
{
        u32 rand = bpf_get_prandom_u32();

        return (rand % 4) == 0;
}

// struct we use for our map keys
struct ip_port_v4 {
        u32 ip;
        u16 port;
        u8 protocol;
        u8 pad;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct ip_port_v4);
        __type(value, u8);
        __uint(max_entries, 1000); // FIXME
} reject_map SEC(".maps");

SEC("socket/check_reject_map")
int check_reject_map(struct __sk_buff *skb)
{
        struct ip_port_v4 key;
        __builtin_memset(&key, 0, sizeof(key));

        // Fill in the key. Note that:
        // 
        // 1. socket filter programs aren't allowed to read skb->data
        //    directly, so we have to do this the old-fashioned way.
        //
        // 2. trying to extract this as a subroutine fails with the
        //    RHEL 8.4 kernel... ("Arg#1 type PTR in get_destination()
        //    is not supported yet.")

        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) != 0)
                return false;
        // no IP options; but this doesn't work under cilium/ebpf because it's a bitfield
        // if (iph.ihl != 5)
        //        return false;

        key.ip = iph.daddr;
        key.protocol = iph.protocol;

        switch (iph.protocol) {
        case IPPROTO_UDP:
                {
                        struct udphdr udp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &udp, sizeof(udp)) != 0)
                                return false;
                        key.port = udp.dest;
                        break;
                }

        case IPPROTO_TCP:
                {
                        struct tcphdr tcp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &tcp, sizeof(tcp)) != 0)
                                return false;
                        key.port = tcp.dest;
                        break;
                }

        case IPPROTO_SCTP:
                {
                        struct sctphdr sctp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &sctp, sizeof(sctp)) != 0)
                                return false;
                        key.port = sctp.dest;
                        break;
                }

        default:
                return false;
        }

        return bpf_map_lookup_elem(&reject_map, &key) != NULL;
}

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, struct ip_port_v4);
        __type(value, u8);
        __uint(max_entries, 1000); // FIXME
} accept_map SEC(".maps");

SEC("socket/check_accept_map")
int check_accept_map(struct __sk_buff *skb)
{
        struct ip_port_v4 key;
        __builtin_memset(&key, 0, sizeof(key));

        // Fill in the key. Note that:
        // 
        // 1. socket filter programs aren't allowed to read skb->data
        //    directly, so we have to do this the old-fashioned way.
        //
        // 2. trying to extract this as a subroutine fails with the
        //    RHEL 8.4 kernel... ("Arg#1 type PTR in get_destination()
        //    is not supported yet.")

        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) != 0)
                return false;
        // no IP options; but this doesn't work under cilium/ebpf because it's a bitfield
        // if (iph.ihl != 5)
        //        return false;

        key.ip = iph.daddr;
        key.protocol = iph.protocol;

        switch (iph.protocol) {
        case IPPROTO_UDP:
                {
                        struct udphdr udp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &udp, sizeof(udp)) != 0)
                                return false;
                        key.port = udp.dest;
                        break;
                }

        case IPPROTO_TCP:
                {
                        struct tcphdr tcp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &tcp, sizeof(tcp)) != 0)
                                return false;
                        key.port = tcp.dest;
                        break;
                }

        case IPPROTO_SCTP:
                {
                        struct sctphdr sctp;
                        if (bpf_skb_load_bytes(skb, sizeof(iph), &sctp, sizeof(sctp)) != 0)
                                return false;
                        key.port = sctp.dest;
                        break;
                }

        default:
                return false;
        }

        return bpf_map_lookup_elem(&accept_map, &key) != NULL;
}
