#ifndef TUNDRA_RULES_H
#define TUNDRA_RULES_H

#include <net/if.h>
#include <stdint.h>
#include <tundra/conf.h>

#define RULES_MAX 256
#define RULES_PORTS_MAX 16
#define RULES_ERR_MAX 160

#define PROTO_TCP 1u
#define PROTO_UDP 2u
#define PROTO_ICMP 4u

enum rule_dir { DIR_IN, DIR_OUT };

struct port_range {
	uint16_t lo;
	uint16_t hi;
};

/* addr and mask in network byte order. */
struct net4 {
	int set;
	uint32_t addr;
	uint32_t mask;
};

struct rule {
	int allow;
	enum rule_dir dir;
	char iface[IF_NAMESIZE];
	unsigned int protos;
	struct port_range ports[RULES_PORTS_MAX];
	int nports;
	struct net4 from;
	struct net4 to;
};

/* What the files say, in order. Without a default block, out is denied. */
struct ruleset {
	int has_default;
	int out_allow;
	struct rule r[RULES_MAX];
	int n;
};

void rules_init(struct ruleset *rs);

/* Adds the blocks of one parsed file. -1 with "line N: why" in err; rs is
 * then of no use. */
int rules_add(struct ruleset *rs, const struct tconf *g,
              char err[RULES_ERR_MAX]);

/* Kernel rules a rule becomes: one per protocol and port range. */
int rules_expanded(const struct rule *r);

#endif
