#ifndef TUNDRA_NFMSG_H
#define TUNDRA_NFMSG_H

#include <stddef.h>
#include <stdint.h>

/* A netlink batch being written into a buffer of the caller. A write that
 * does not fit sets overflow and the batch is of no use. */
struct nfbuf {
	unsigned char *data;
	size_t size;
	size_t len;
	int overflow;
	uint32_t seq;
	size_t msg;
};

void nfbuf_init(struct nfbuf *b, unsigned char *data, size_t size,
                uint32_t seq);

/* A message of the nf_tables subsystem; nfmsg_end closes it and gives its
 * sequence number. */
void nfmsg_begin(struct nfbuf *b, int type, int flags, int family);
uint32_t nfmsg_end(struct nfbuf *b);
void nfmsg_batch(struct nfbuf *b, int begin);

void nfattr_put(struct nfbuf *b, int type, const void *data, size_t len);
void nfattr_str(struct nfbuf *b, int type, const char *s);
void nfattr_be32(struct nfbuf *b, int type, uint32_t v);
size_t nfattr_nest(struct nfbuf *b, int type);
void nfattr_nest_end(struct nfbuf *b, size_t at);

#endif
