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
