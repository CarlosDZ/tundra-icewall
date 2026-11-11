#include "nfmsg.h"

#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <string.h>

void nfbuf_init(struct nfbuf *b, unsigned char *data, size_t size,
                uint32_t seq) {
	memset(b, 0, sizeof(*b));
	b->data = data;
	b->size = size;
	b->seq = seq;
}

static void *reserve(struct nfbuf *b, size_t len) {
	size_t padded = NLMSG_ALIGN(len);
	if (b->overflow || padded > b->size - b->len) {
		b->overflow = 1;
		return NULL;
	}
	void *p = b->data + b->len;
	memset(p, 0, padded);
	b->len += padded;
	return p;
}

static void header(struct nfbuf *b, int type, int flags, int family,
                   int res_id) {
	b->msg = b->len;
	struct nlmsghdr *nlh = reserve(b, sizeof(*nlh));
	struct nfgenmsg *nfg = reserve(b, sizeof(*nfg));
	if (!nlh || !nfg)
		return;
	nlh->nlmsg_type = (uint16_t)type;
	nlh->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | flags);
	nlh->nlmsg_seq = b->seq;
	nfg->nfgen_family = (uint8_t)family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons((uint16_t)res_id);
}

void nfmsg_begin(struct nfbuf *b, int type, int flags, int family) {
	header(b, (NFNL_SUBSYS_NFTABLES << 8) | type, flags, family, 0);
}

uint32_t nfmsg_end(struct nfbuf *b) {
	if (!b->overflow) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)(b->data + b->msg);
		nlh->nlmsg_len = (uint32_t)(b->len - b->msg);
	}
	return b->seq++;
}

void nfmsg_batch(struct nfbuf *b, int begin) {
	header(b, begin ? NFNL_MSG_BATCH_BEGIN : NFNL_MSG_BATCH_END, 0, 0,
	       NFNL_SUBSYS_NFTABLES);
	nfmsg_end(b);
}

void nfattr_put(struct nfbuf *b, int type, const void *data, size_t len) {
	struct nlattr *a = reserve(b, NLA_HDRLEN + len);
	if (!a)
		return;
	a->nla_type = (uint16_t)type;
	a->nla_len = (uint16_t)(NLA_HDRLEN + len);
	if (len)
		memcpy((unsigned char *)a + NLA_HDRLEN, data, len);
}

void nfattr_str(struct nfbuf *b, int type, const char *s) {
	nfattr_put(b, type, s, strlen(s) + 1);
}

void nfattr_be32(struct nfbuf *b, int type, uint32_t v) {
	uint32_t be = htonl(v);
	nfattr_put(b, type, &be, sizeof(be));
}

size_t nfattr_nest(struct nfbuf *b, int type) {
	size_t at = b->len;
	struct nlattr *a = reserve(b, NLA_HDRLEN);
	if (a)
		a->nla_type = (uint16_t)(type | NLA_F_NESTED);
	return at;
}

void nfattr_nest_end(struct nfbuf *b, size_t at) {
	if (b->overflow)
		return;
	struct nlattr *a = (struct nlattr *)(b->data + at);
	/* nla_len is 16 bits: a nest that large would wrap. */
	if (b->len - at > 0xffff) {
		b->overflow = 1;
		return;
	}
	a->nla_len = (uint16_t)(b->len - at);
}
