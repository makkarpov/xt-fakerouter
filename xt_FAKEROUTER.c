#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "fakert_info.h"

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/checksum.h>

#define NEXTHDR_ICMP6 58

static void send_ttl_exceeded(struct net *net, struct sk_buff *oldskb, struct in6_addr *src_addr) {
	size_t max_reply_sz, reply_sz, csum_sz, total_sz;
	int hh_len;
	struct sk_buff *nskb;
	struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;
	struct dst_entry *dst = NULL;
	struct flowi6 fl6;
	
	max_reply_sz = oldskb->dev->mtu - sizeof(struct ipv6hdr) - sizeof(struct icmp6hdr);
	reply_sz = oldskb->len;
	
	if (reply_sz > max_reply_sz) {
		reply_sz = max_reply_sz;
	}
	
	csum_sz = sizeof(struct icmp6hdr) + reply_sz;
	total_sz = sizeof(struct ipv6hdr) + csum_sz;
	
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_ICMP;
	fl6.saddr = *src_addr;
	fl6.daddr = ipv6_hdr(oldskb)->saddr;
	fl6.flowi6_oif = oldskb->dev->ifindex;
	security_skb_classify_flow(oldskb, flowi6_to_flowi(&fl6));
	dst = ip6_route_output(net, NULL, &fl6);
	
	if (dst->error) {
		dst_release(dst);
		return;
	}
	
	dst = xfrm_lookup(net, dst, flowi6_to_flowi(&fl6), NULL, 0);
	if (IS_ERR(dst)) {
		// TODO: No dst_release here?
		return;
	}
	
	hh_len = (dst->dev->hard_header_len + 15) & ~15;
	nskb = alloc_skb(hh_len + 15 + dst->header_len + total_sz + dst->trailer_len, GFP_ATOMIC);
	if (!nskb) {
		printk("cannot alloc skb");
		dst_release(dst);
		return;
	}
	
	skb_dst_set(nskb, dst);
	nskb->mark = fl6.flowi6_mark;
	skb_reserve(nskb, hh_len + 15 + dst->header_len);
	
	skb_reset_network_header(nskb);
	ip6h = (struct ipv6hdr *) skb_put(nskb, sizeof(struct ipv6hdr));
	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->hop_limit = ip6_dst_hoplimit(dst);
	ip6h->nexthdr = NEXTHDR_ICMP6;
	ip6h->saddr = fl6.saddr;
	ip6h->daddr = fl6.daddr;
	nskb->protocol = htons(ETH_P_IPV6);
	
	skb_reset_transport_header(nskb);
	icmp6h = (struct icmp6hdr*) skb_put(nskb, csum_sz);
	icmp6h->icmp6_type = 3;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_dataun.un_data32[0] = 0;
	icmp6h->icmp6_cksum = 0;
	
	memcpy((u8*) icmp6h + sizeof(struct icmp6hdr), oldskb->data, reply_sz);
	
	icmp6h->icmp6_cksum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, csum_sz, NEXTHDR_ICMP6, csum_partial(icmp6h, csum_sz, 0));
	
//	print_hex_dump(KERN_INFO, "FAKEROUTER: ", DUMP_PREFIX_OFFSET, 16, 1, nskb->data, nskb->len, 1);
	
	nf_ct_attach(nskb, oldskb);
	ip6_local_out(nskb);
}

static unsigned int
fakert_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_fakert_info *rtinfo = par->targinfo;
	struct ipv6hdr *ip6h;

	ip6h = ipv6_hdr(skb);
	
	if (ip6h->hop_limit < rtinfo->router_count + 1) {
		struct in6_addr src_addr = ip6h->daddr;
		src_addr.s6_addr16[7] = htons(ip6h->hop_limit);
		send_ttl_exceeded(dev_net(skb->dev), skb, &src_addr);
		return NF_DROP;
	}
	
	return XT_CONTINUE;
}

static int fakert_tg_check(const struct xt_tgchk_param *par)
{
	const struct xt_fakert_info *rtinfo = par->targinfo;

	if (rtinfo->router_count > 128) {
		return -EINVAL;
	}

	return 0;
}

static struct xt_target fakert_tg_regs __read_mostly = {
	.name		= "FAKEROUTER",
	.family		= NFPROTO_IPV6,
	.target		= fakert_tg,
	.targetsize	= sizeof(struct xt_fakert_info),
	.checkentry	= fakert_tg_check,
	.me			= THIS_MODULE,
};

static int __init log_tg_init(void)
{
	return xt_register_target(&fakert_tg_regs);
}

static void __exit log_tg_exit(void)
{
	xt_unregister_target(&fakert_tg_regs);
}

module_init(log_tg_init);
module_exit(log_tg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maxim Karpov <me@makkarpov.ru>");
MODULE_DESCRIPTION("Xtables: Emulation of chain of routers at IPv6 address");
MODULE_ALIAS("ipt_FAKEROUTER");
MODULE_ALIAS("ip6t_FAKEROUTER");
