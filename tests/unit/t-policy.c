#include "nfmsg.c"
#include "policy.c"
#include "rules.c"
#include "test.h"

#include <linux/netfilter/nfnetlink.h>

static unsigned char buf[65536];
static struct ruleset rs;

static int messages(const struct nfbuf *b, int type) {
	int n = 0;
	size_t at = 0;
	while (at + sizeof(struct nlmsghdr) <= b->len) {
		const struct nlmsghdr *nlh = (const struct nlmsghdr *)(b->data + at);
		if (nlh->nlmsg_len < sizeof(*nlh) || at + nlh->nlmsg_len > b->len)
			return -1;
		n += nlh->nlmsg_type == type;
		at += NLMSG_ALIGN(nlh->nlmsg_len);
	}
	return at == b->len ? n : -1;
}

#define NFT(type) ((NFNL_SUBSYS_NFTABLES << 8) | (type))
#define FIXED_RULES 13

int main(void) {
	struct nfbuf b;

	rules_init(&rs);
	nfbuf_init(&b, buf, sizeof(buf), 1);
	uint32_t last = policy_build(&b, &rs);
	CHECK(last && !b.overflow, "the fixed policy fits");
	CHECK(messages(&b, NFNL_MSG_BATCH_BEGIN) == 1 &&
	          messages(&b, NFNL_MSG_BATCH_END) == 1,
	      "one transaction, opened and closed");
	CHECK(((const struct nlmsghdr *)b.data)->nlmsg_type == NFNL_MSG_BATCH_BEGIN,
	      "that starts the batch");
	CHECK(messages(&b, NFT(NFT_MSG_DESTROYTABLE)) == 1 &&
	          messages(&b, NFT(NFT_MSG_NEWTABLE)) == 1,
	      "the table is destroyed and created in it");
	CHECK(messages(&b, NFT(NFT_MSG_NEWCHAIN)) == 4,
	      "four chains: forward, strong, input and output");
	CHECK(messages(&b, NFT(NFT_MSG_NEWRULE)) == FIXED_RULES,
	      "and the fixed rules, the default of the output last");
	CHECK(last == b.seq - 2, "the last rule is the one acknowledged");

	rs.n = 2;
	rs.r[0] = (struct rule){.allow = 1,
	                        .dir = DIR_IN,
	                        .protos = PROTO_TCP | PROTO_UDP,
	                        .ports = {{22, 22}, {80, 90}, {443, 443}},
	                        .nports = 3};
	rs.r[1] = (struct rule){.allow = 0, .dir = DIR_OUT};
	nfbuf_init(&b, buf, sizeof(buf), 1);
	policy_build(&b, &rs);
	CHECK(policy_count(&rs) == 7 &&
	          messages(&b, NFT(NFT_MSG_NEWRULE)) == FIXED_RULES + 7,
	      "a rule becomes one per protocol and port range");

	nfbuf_init(&b, buf, sizeof(buf), 1);
	last = policy_lockdown(&b);
	CHECK(last && messages(&b, NFT(NFT_MSG_NEWCHAIN)) == 3 &&
	          messages(&b, NFT(NFT_MSG_NEWRULE)) == 3,
	      "the lockdown: three chains, local traffic and nothing else");

	nfbuf_init(&b, buf, 512, 1);
	CHECK(policy_build(&b, &rs) == 0 && b.overflow,
	      "a policy that does not fit is refused, not cut");
	nfbuf_init(&b, buf, 64, 1);
	CHECK(policy_lockdown(&b) == 0, "and so is a lockdown");

	nfbuf_init(&b, buf, sizeof(buf), 7);
	CHECK(policy_query(&b) == 7 && messages(&b, NFT(NFT_MSG_GETTABLE)) == 1,
	      "the query for the table");
	return test_summary();
}
