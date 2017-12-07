/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") source_drop = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 256,
};

struct parse_position {
	void *data;
	void *data_end;
	u64 nh_off;
};

static bool get_ipv4_header(struct iphdr **iph, struct parse_position *p)
{
	*iph = p->data + p->nh_off;

	if (*iph + 1 > p->data_end)
		return ENOMEM;
	return 0;
}

#ifdef NOT_YET_IPV6
static int get_ipv6_header(struct ipv6hdr **ip6h, struct parse_position *p)
{
	*ip6h = p->data + nh_off;

	if (*ip6h + 1 > p->data_end)
		return ENOMEM;
	return 0;
}
#endif

static bool remove_vlan(u16 *h_proto, struct parse_position *p)
{
	if (*h_proto == ETH_P_8021Q || *h_proto == ETH_P_8021AD) {
		struct vlan_hdr *vhdr;

		vhdr = p->data + p->nh_off;
		p->nh_off += sizeof(struct vlan_hdr);
		if (p->data + p->nh_off > p->data_end)
			return ENOMEM;
		*h_proto = ntohs(vhdr->h_vlan_encapsulated_proto);
	}
	return 0;
}

static int get_proto(u16 *h_proto, struct parse_position *p)
{
	struct ethhdr *eth = p->data;
	int rc;

	p->nh_off += sizeof(*eth);
	if (p->data + p->nh_off > p->data_end)
		return ENOMEM;
	
	*h_proto = ntohs(eth->h_proto);

	if ((rc = remove_vlan(h_proto, p)))
		return rc;
	/* may be double-tagged */
	if ((rc =remove_vlan(h_proto, p)))
		return rc;
	return 0;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	struct parse_position p = {
		.data = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
		.nh_off = 0,
	};
	u32 *value;
	u16 h_proto;
	struct iphdr *iph;
	u32 ip_addr;

	if (get_proto(&h_proto, &p))
		return XDP_PASS;

	if (h_proto != ETH_P_IP)
		return XDP_PASS;
	
	if (get_ipv4_header(&iph, &p))
		return XDP_PASS;
	
#ifdef NOT_YET_IPV6	
	else if (h_proto == ETH_P_IPV6)
		ipproto = parse_ipv6(&p);
#endif

	value = bpf_map_lookup_elem(&source_drop, &iph->saddr);
	if (value && *value)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
