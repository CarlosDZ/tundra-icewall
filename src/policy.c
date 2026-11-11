#include "policy.h"

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>

#define FAMILY NFPROTO_INET
#define CHAIN_IN "input"
#define CHAIN_OUT "output"
#define CHAIN_FWD "forward"
#define CHAIN_STRONG "strong"

#define IP_SADDR 12
#define IP_DADDR 16
#define L4_DPORT 2

static void table_msg(struct nfbuf *b, int type, int flags, const char *state) {
	nfmsg_begin(b, type, flags, FAMILY);
	nfattr_str(b, NFTA_TABLE_NAME, POLICY_TABLE);
	if (state)
		nfattr_put(b, NFTA_TABLE_USERDATA, state, strlen(state));
	nfmsg_end(b);
}

static void chain(struct nfbuf *b, const char *name, int hook, int accept) {
	nfmsg_begin(b, NFT_MSG_NEWCHAIN, NLM_F_CREATE, FAMILY);
	nfattr_str(b, NFTA_CHAIN_TABLE, POLICY_TABLE);
	nfattr_str(b, NFTA_CHAIN_NAME, name);
	if (hook >= 0) {
		size_t h = nfattr_nest(b, NFTA_CHAIN_HOOK);
		nfattr_be32(b, NFTA_HOOK_HOOKNUM, (uint32_t)hook);
		nfattr_be32(b, NFTA_HOOK_PRIORITY, 0);
		nfattr_nest_end(b, h);
		nfattr_be32(b, NFTA_CHAIN_POLICY, accept ? NF_ACCEPT : NF_DROP);
		nfattr_str(b, NFTA_CHAIN_TYPE, "filter");
	}
	nfmsg_end(b);
}

struct rule_msg {
	struct nfbuf *b;
	size_t exprs;
};

static struct rule_msg rule_begin(struct nfbuf *b, const char *chain_name) {
	nfmsg_begin(b, NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND, FAMILY);
	nfattr_str(b, NFTA_RULE_TABLE, POLICY_TABLE);
	nfattr_str(b, NFTA_RULE_CHAIN, chain_name);
	return (struct rule_msg){b, nfattr_nest(b, NFTA_RULE_EXPRESSIONS)};
}

static uint32_t rule_end(struct rule_msg *m) {
	nfattr_nest_end(m->b, m->exprs);
	return nfmsg_end(m->b);
}

struct expr {
	struct nfbuf *b;
	size_t elem;
	size_t data;
};

static struct expr expr_begin(struct nfbuf *b, const char *name) {
	struct expr e = {b, nfattr_nest(b, NFTA_LIST_ELEM), 0};
	nfattr_str(b, NFTA_EXPR_NAME, name);
	e.data = nfattr_nest(b, NFTA_EXPR_DATA);
	return e;
}

static void expr_end(struct expr *e) {
	nfattr_nest_end(e->b, e->data);
	nfattr_nest_end(e->b, e->elem);
}

static void value(struct nfbuf *b, int type, const void *data, size_t len) {
	size_t n = nfattr_nest(b, type);
	nfattr_put(b, NFTA_DATA_VALUE, data, len);
	nfattr_nest_end(b, n);
}

static void meta(struct nfbuf *b, uint32_t key) {
	struct expr e = expr_begin(b, "meta");
	nfattr_be32(b, NFTA_META_DREG, NFT_REG_1);
	nfattr_be32(b, NFTA_META_KEY, key);
	expr_end(&e);
}

static void cmp(struct nfbuf *b, uint32_t op, const void *data, size_t len) {
	struct expr e = expr_begin(b, "cmp");
	nfattr_be32(b, NFTA_CMP_SREG, NFT_REG_1);
	nfattr_be32(b, NFTA_CMP_OP, op);
	value(b, NFTA_CMP_DATA, data, len);
	expr_end(&e);
}

static void mask(struct nfbuf *b, const void *m, size_t len) {
	static const unsigned char zero[4];
	struct expr e = expr_begin(b, "bitwise");
	nfattr_be32(b, NFTA_BITWISE_SREG, NFT_REG_1);
	nfattr_be32(b, NFTA_BITWISE_DREG, NFT_REG_1);
	nfattr_be32(b, NFTA_BITWISE_LEN, (uint32_t)len);
	value(b, NFTA_BITWISE_MASK, m, len);
	value(b, NFTA_BITWISE_XOR, zero, len);
	expr_end(&e);
}

static void payload(struct nfbuf *b, uint32_t base, uint32_t offset,
                    uint32_t len) {
	struct expr e = expr_begin(b, "payload");
	nfattr_be32(b, NFTA_PAYLOAD_DREG, NFT_REG_1);
	nfattr_be32(b, NFTA_PAYLOAD_BASE, base);
	nfattr_be32(b, NFTA_PAYLOAD_OFFSET, offset);
	nfattr_be32(b, NFTA_PAYLOAD_LEN, len);
	expr_end(&e);
}

static void verdict(struct nfbuf *b, int code, const char *chain_name) {
	struct expr e = expr_begin(b, "immediate");
	nfattr_be32(b, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
	size_t d = nfattr_nest(b, NFTA_IMMEDIATE_DATA);
	size_t v = nfattr_nest(b, NFTA_DATA_VERDICT);
	nfattr_be32(b, NFTA_VERDICT_CODE, (uint32_t)code);
	if (chain_name)
		nfattr_str(b, NFTA_VERDICT_CHAIN, chain_name);
	nfattr_nest_end(b, v);
	nfattr_nest_end(b, d);
	expr_end(&e);
}

static void match_iface(struct nfbuf *b, int in, const char *name) {
	char padded[IF_NAMESIZE] = {0};
	strncpy(padded, name, sizeof(padded) - 1);
	meta(b, in ? NFT_META_IIFNAME : NFT_META_OIFNAME);
	cmp(b, NFT_CMP_EQ, padded, sizeof(padded));
}

/* ct state is a bit mask in host order. */
static void match_ct(struct nfbuf *b, uint32_t states) {
	struct expr e = expr_begin(b, "ct");
	nfattr_be32(b, NFTA_CT_DREG, NFT_REG_1);
	nfattr_be32(b, NFTA_CT_KEY, NFT_CT_STATE);
	expr_end(&e);
	uint32_t none = 0;
	mask(b, &states, sizeof(states));
	cmp(b, NFT_CMP_NEQ, &none, sizeof(none));
}

static uint32_t simple(struct nfbuf *b, const char *chain_name, int code,
                       const char *target) {
	struct rule_msg m = rule_begin(b, chain_name);
	verdict(b, code, target);
	return rule_end(&m);
}

static void local_rule(struct nfbuf *b, const char *chain_name, int in) {
	struct rule_msg m = rule_begin(b, chain_name);
	match_iface(b, in, "lo");
	verdict(b, NF_ACCEPT, NULL);
	rule_end(&m);
}

static void ipv6_rule(struct nfbuf *b, const char *chain_name) {
	uint8_t v6 = NFPROTO_IPV6;
	struct rule_msg m = rule_begin(b, chain_name);
	meta(b, NFT_META_NFPROTO);
	cmp(b, NFT_CMP_EQ, &v6, sizeof(v6));
	verdict(b, NF_DROP, NULL);
	rule_end(&m);
}

static void ct_rule(struct nfbuf *b, const char *chain_name, uint32_t states,
                    int code) {
	struct rule_msg m = rule_begin(b, chain_name);
	match_ct(b, states);
	verdict(b, code, NULL);
	rule_end(&m);
}

/* ADR-021: what arrives on an interface for an address that is not local to
 * it, nor broadcast or multicast, is dropped. */
static void strong_chain(struct nfbuf *b) {
	static const uint32_t fine[] = {RTN_LOCAL, RTN_BROADCAST, RTN_MULTICAST};
	chain(b, CHAIN_STRONG, -1, 0);
	for (size_t i = 0; i < sizeof(fine) / sizeof(fine[0]); i++) {
		struct rule_msg m = rule_begin(b, CHAIN_STRONG);
		struct expr e = expr_begin(b, "fib");
		nfattr_be32(b, NFTA_FIB_DREG, NFT_REG_1);
		nfattr_be32(b, NFTA_FIB_RESULT, NFT_FIB_RESULT_ADDRTYPE);
		nfattr_be32(b, NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR | NFTA_FIB_F_IIF);
		expr_end(&e);
		cmp(b, NFT_CMP_EQ, &fine[i], sizeof(fine[i]));
		verdict(b, NFT_RETURN, NULL);
		rule_end(&m);
	}
	simple(b, CHAIN_STRONG, NF_DROP, NULL);
}

static void match_net(struct nfbuf *b, const struct net4 *n, uint32_t offset) {
	if (!n->set || !n->mask)
		return;
	payload(b, NFT_PAYLOAD_NETWORK_HEADER, offset, 4);
	if (n->mask != 0xffffffffu)
		mask(b, &n->mask, sizeof(n->mask));
	cmp(b, NFT_CMP_EQ, &n->addr, sizeof(n->addr));
}

static void user_rule(struct nfbuf *b, const struct rule *r, int proto,
                      const struct port_range *pr) {
	int in = r->dir == DIR_IN;
	struct rule_msg m = rule_begin(b, in ? CHAIN_IN : CHAIN_OUT);
	if (r->iface[0])
		match_iface(b, in, r->iface);
	if (proto) {
		uint8_t p = (uint8_t)proto;
		meta(b, NFT_META_L4PROTO);
		cmp(b, NFT_CMP_EQ, &p, sizeof(p));
	}
	if ((r->from.set && r->from.mask) || (r->to.set && r->to.mask)) {
		uint8_t v4 = NFPROTO_IPV4;
		meta(b, NFT_META_NFPROTO);
		cmp(b, NFT_CMP_EQ, &v4, sizeof(v4));
	}
	match_net(b, &r->from, IP_SADDR);
	match_net(b, &r->to, IP_DADDR);
	if (pr) {
		uint16_t lo = htons(pr->lo), hi = htons(pr->hi);
		payload(b, NFT_PAYLOAD_TRANSPORT_HEADER, L4_DPORT, 2);
		if (pr->lo == pr->hi) {
			cmp(b, NFT_CMP_EQ, &lo, sizeof(lo));
		} else {
			cmp(b, NFT_CMP_GTE, &lo, sizeof(lo));
			cmp(b, NFT_CMP_LTE, &hi, sizeof(hi));
		}
	}
	verdict(b, r->allow ? NF_ACCEPT : NF_DROP, NULL);
	rule_end(&m);
}

static void user_rules(struct nfbuf *b, const struct ruleset *rs,
                       enum rule_dir dir) {
	static const struct {
		unsigned int bit;
		int number;
	} protos[] = {{PROTO_TCP, IPPROTO_TCP},
	              {PROTO_UDP, IPPROTO_UDP},
	              {PROTO_ICMP, IPPROTO_ICMP}};
	for (int i = 0; i < rs->n; i++) {
		const struct rule *r = &rs->r[i];
		if (r->dir != dir)
			continue;
		for (size_t p = 0; p < sizeof(protos) / sizeof(protos[0]); p++) {
			if (r->protos && !(r->protos & protos[p].bit))
				continue;
			int number = r->protos ? protos[p].number : 0;
			for (int k = 0; k < (r->nports ? r->nports : 1); k++)
				user_rule(b, r, number, r->nports ? &r->ports[k] : NULL);
			if (!r->protos)
				break;
		}
	}
}

/* The table goes away and comes back in the same transaction: no packet sees
 * half a policy. DESTROY does not fail when there is none yet. */
static void replace_table(struct nfbuf *b, const char *state) {
	nfmsg_batch(b, 1);
	table_msg(b, NFT_MSG_DESTROYTABLE, 0, NULL);
	table_msg(b, NFT_MSG_NEWTABLE, NLM_F_CREATE, state);
}

static uint32_t finish(struct nfbuf *b, const char *chain_name, int accept) {
	/* The last message asks for the acknowledgement that closes the batch. */
	struct rule_msg m = rule_begin(b, chain_name);
	verdict(b, accept ? NF_ACCEPT : NF_DROP, NULL);
	struct nlmsghdr *nlh = (struct nlmsghdr *)(b->data + b->msg);
	if (!b->overflow)
		nlh->nlmsg_flags |= NLM_F_ACK;
	uint32_t last = rule_end(&m);
	nfmsg_batch(b, 0);
	return b->overflow ? 0 : last;
}

int policy_count(const struct ruleset *rs) {
	int n = 0;
	for (int i = 0; i < rs->n; i++)
		n += rules_expanded(&rs->r[i]);
	return n;
}

uint32_t policy_build(struct nfbuf *b, const struct ruleset *rs) {
	uint32_t established =
	    NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED);
	replace_table(b, POLICY_STATE_POLICY);
	chain(b, CHAIN_FWD, NF_INET_FORWARD, 0);
	strong_chain(b);

	chain(b, CHAIN_IN, NF_INET_LOCAL_IN, 0);
	local_rule(b, CHAIN_IN, 1);
	ipv6_rule(b, CHAIN_IN);
	ct_rule(b, CHAIN_IN, NF_CT_STATE_INVALID_BIT, NF_DROP);
	ct_rule(b, CHAIN_IN, established, NF_ACCEPT);
	simple(b, CHAIN_IN, NFT_JUMP, CHAIN_STRONG);
	user_rules(b, rs, DIR_IN);

	chain(b, CHAIN_OUT, NF_INET_LOCAL_OUT, 0);
	local_rule(b, CHAIN_OUT, 0);
	ipv6_rule(b, CHAIN_OUT);
	ct_rule(b, CHAIN_OUT, established, NF_ACCEPT);
	user_rules(b, rs, DIR_OUT);
	return finish(b, CHAIN_OUT, rs->has_default && rs->out_allow);
}

uint32_t policy_lockdown(struct nfbuf *b) {
	replace_table(b, POLICY_STATE_LOCKDOWN);
	chain(b, CHAIN_FWD, NF_INET_FORWARD, 0);
	chain(b, CHAIN_IN, NF_INET_LOCAL_IN, 0);
	local_rule(b, CHAIN_IN, 1);
	chain(b, CHAIN_OUT, NF_INET_LOCAL_OUT, 0);
	local_rule(b, CHAIN_OUT, 0);
	return finish(b, CHAIN_OUT, 0);
}

uint32_t policy_query(struct nfbuf *b) {
	nfmsg_begin(b, NFT_MSG_GETTABLE, NLM_F_ACK, FAMILY);
	nfattr_str(b, NFTA_TABLE_NAME, POLICY_TABLE);
	uint32_t seq = nfmsg_end(b);
	return b->overflow ? 0 : seq;
}
