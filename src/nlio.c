#include "nlio.h"

#include <errno.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int nlio_open(size_t sndbuf) {
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0)
		return -1;
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	int size = (int)sndbuf;
	/* A batch is one datagram: it has to fit in the send buffer. FORCE needs
	 * CAP_NET_ADMIN; without it the plain option is the best there is. */
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &size, sizeof(size)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int wait_input(int fd) {
	struct pollfd p = {.fd = fd, .events = POLLIN};
	for (;;) {
		int r = poll(&p, 1, NLIO_TIMEOUT_MS);
		if (r > 0)
			return 0;
		if (r == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (errno != EINTR)
			return -1;
	}
}

static ssize_t receive(int fd, unsigned char *buf, size_t size) {
	for (;;) {
		if (wait_input(fd) < 0)
			return -1;
		ssize_t n = recvfrom(fd, buf, size, 0, NULL, NULL);
		if (n >= 0 || (errno != EINTR && errno != EAGAIN))
			return n;
	}
}

static int send_all(int fd, const unsigned char *data, size_t len) {
	struct sockaddr_nl to = {.nl_family = AF_NETLINK};
	for (;;) {
		ssize_t n =
		    sendto(fd, data, len, 0, (struct sockaddr *)&to, sizeof(to));
		if (n == (ssize_t)len)
			return 0;
		if (n >= 0) {
			errno = EMSGSIZE;
			return -1;
		}
		if (errno != EINTR)
			return -1;
	}
}

int nlio_commit(int fd, const unsigned char *data, size_t len, uint32_t first,
                uint32_t last) {
	static unsigned char buf[16384];
	if (send_all(fd, data, len) < 0)
		return -1;
	int failed = 0;
	for (;;) {
		ssize_t n = receive(fd, buf, sizeof(buf));
		if (n < 0) {
			if (failed)
				errno = failed;
			return -1;
		}
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		for (; NLMSG_OK(nlh, (size_t)n); nlh = NLMSG_NEXT(nlh, n)) {
			if (nlh->nlmsg_type != NLMSG_ERROR)
				continue;
			const struct nlmsgerr *e = NLMSG_DATA(nlh);
			/* The first refusal is the one that explains the rest. */
			if (e->error && !failed)
				failed = -e->error;
			/* The kernel answers every refused message and, always, the
			 * last one. A refusal of the transaction as a whole comes on its
			 * first message instead, and nothing follows. */
			int closes = e->msg.nlmsg_seq == last ||
			             (e->error && e->msg.nlmsg_seq == first);
			if (!closes)
				continue;
			if (failed) {
				errno = failed;
				return -1;
			}
			return 0;
		}
	}
}

int nlio_table_state(int fd, const unsigned char *data, size_t len,
                     uint32_t seq, char state[NLIO_STATE_MAX]) {
	static unsigned char buf[16384];
	if (send_all(fd, data, len) < 0)
		return -1;
	int found = 0;
	state[0] = '\0';
	for (;;) {
		ssize_t n = receive(fd, buf, sizeof(buf));
		if (n < 0)
			return -1;
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
		for (; NLMSG_OK(nlh, (size_t)n); nlh = NLMSG_NEXT(nlh, n)) {
			if (nlh->nlmsg_seq != seq)
				continue;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *e = NLMSG_DATA(nlh);
				if (e->error == -ENOENT)
					return 0;
				if (e->error) {
					errno = -e->error;
					return -1;
				}
				return found;
			}
			if (nlh->nlmsg_type !=
			    ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE))
				continue;
			found = 1;
			size_t hdr = NLMSG_LENGTH(sizeof(struct nfgenmsg));
			if (nlh->nlmsg_len < hdr)
				continue;
			const struct nlattr *a =
			    (const struct nlattr *)((const unsigned char *)nlh + hdr);
			size_t left = nlh->nlmsg_len - hdr;
			while (left >= NLA_HDRLEN && a->nla_len >= NLA_HDRLEN &&
			       a->nla_len <= left) {
				if ((a->nla_type & NLA_TYPE_MASK) == NFTA_TABLE_USERDATA) {
					size_t dl = a->nla_len - NLA_HDRLEN;
					if (dl >= NLIO_STATE_MAX)
						dl = NLIO_STATE_MAX - 1;
					memcpy(state, (const unsigned char *)a + NLA_HDRLEN, dl);
					state[dl] = '\0';
				}
				size_t step = NLA_ALIGN(a->nla_len);
				if (step > left)
					break;
				left -= step;
				a = (const struct nlattr *)((const unsigned char *)a + step);
			}
		}
	}
}
