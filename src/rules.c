#include "rules.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum key {
	K_DIRECTION,
	K_INTERFACE,
	K_PROTOCOL,
	K_PORT,
	K_FROM,
	K_TO,
	K_COUNT
};

static const char *const key_names[K_COUNT] = {
    "direction", "interface", "protocol", "port", "from", "to"};

static int fail(char err[RULES_ERR_MAX], int line, const char *fmt, ...) {
	char msg[RULES_ERR_MAX - 16];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	snprintf(err, RULES_ERR_MAX, "line %d: %s", line, msg);
	return -1;
}

void rules_init(struct ruleset *rs) { memset(rs, 0, sizeof(*rs)); }

static int valid_ifname(const char *s) {
	size_t n = strlen(s);
	if (n == 0 || n >= IF_NAMESIZE || strcmp(s, ".") == 0 ||
	    strcmp(s, "..") == 0)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (s[i] == '/' || s[i] == ' ' || s[i] == '\t' || s[i] == ':')
			return 0;
	return 1;
}

/* The next element of a comma separated list, trimmed; NULL at the end. An
 * empty element comes back as "". */
static char *next_elem(char **cursor) {
	char *s = *cursor;
	if (!s)
		return NULL;
	char *comma = strchr(s, ',');
	if (comma) {
		*comma = '\0';
		*cursor = comma + 1;
	} else {
		*cursor = NULL;
	}
	while (*s == ' ' || *s == '\t')
		s++;
	size_t n = strlen(s);
	while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
	return s;
}

static int parse_protocol(struct rule *r, const struct tconf_item *it,
                          char *err) {
	char buf[TCONF_VALUE_MAX], *cur = buf;
	snprintf(buf, sizeof(buf), "%s", it->value);
	for (char *e; (e = next_elem(&cur));) {
		unsigned int bit;
		if (strcmp(e, "tcp") == 0)
			bit = PROTO_TCP;
		else if (strcmp(e, "udp") == 0)
			bit = PROTO_UDP;
		else if (strcmp(e, "icmp") == 0)
			bit = PROTO_ICMP;
		else
			return fail(err, it->line, "invalid protocol: %s",
			            *e ? e : "(empty)");
		if (r->protos & bit)
			return fail(err, it->line, "repeated protocol: %s", e);
		r->protos |= bit;
	}
	return 0;
}

static int parse_number(const char *s, size_t n, long max, long *out) {
	if (n == 0 || n > 5)
		return -1;
	long v = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9')
			return -1;
		v = v * 10 + (s[i] - '0');
	}
	if (v > max)
		return -1;
	*out = v;
	return 0;
}

static int parse_port(struct rule *r, const struct tconf_item *it, char *err) {
	char buf[TCONF_VALUE_MAX], *cur = buf;
	snprintf(buf, sizeof(buf), "%s", it->value);
	for (char *e; (e = next_elem(&cur));) {
		const char *dash = strchr(e, '-');
		size_t first = dash ? (size_t)(dash - e) : strlen(e);
		long lo, hi;
		if (parse_number(e, first, 65535, &lo) < 0 || lo == 0)
			return fail(err, it->line, "invalid port: %s", *e ? e : "(empty)");
		hi = lo;
		if (dash && (parse_number(dash + 1, strlen(dash + 1), 65535, &hi) < 0 ||
		             hi < lo))
			return fail(err, it->line, "invalid port range: %s", e);
		if (r->nports == RULES_PORTS_MAX)
			return fail(err, it->line, "more than %d ports or ranges",
			            RULES_PORTS_MAX);
		r->ports[r->nports].lo = (uint16_t)lo;
		r->ports[r->nports++].hi = (uint16_t)hi;
	}
	return 0;
}

static int parse_net(struct net4 *n, const struct tconf_item *it, char *err) {
	char buf[TCONF_VALUE_MAX];
	snprintf(buf, sizeof(buf), "%s", it->value);
	char *slash = strchr(buf, '/');
	long prefix = 32;
	if (slash) {
		*slash = '\0';
		if (parse_number(slash + 1, strlen(slash + 1), 32, &prefix) < 0)
			return fail(err, it->line, "invalid prefix in %s: %s", it->key,
			            it->value);
	}
	struct in_addr a;
	if (inet_pton(AF_INET, buf, &a) != 1)
		return fail(err, it->line, "invalid address in %s: %s", it->key,
		            it->value);
	uint32_t mask = prefix ? htonl(0xffffffffu << (32 - prefix)) : 0;
	if (a.s_addr & ~mask)
		return fail(err, it->line, "%s has bits outside its prefix: %s",
		            it->key, it->value);
	n->set = 1;
	n->addr = a.s_addr;
	n->mask = mask;
	return 0;
}

static int add_default(struct ruleset *rs, const struct tconf *g, int block,
                       char *err) {
	const struct tconf_item *out = NULL;
	if (rs->has_default)
		return fail(err, g->blocks[block].line, "a second default block");
	for (int i = 0; i < g->n; i++) {
		const struct tconf_item *it = &g->items[i];
		if (it->block != block)
			continue;
		if (strcmp(it->key, "out") != 0)
			return fail(err, it->line, "unknown key %s in default", it->key);
		if (out)
			return fail(err, it->line, "repeated key out");
		if (it->quoted)
			return fail(err, it->line, "out must not be quoted");
		out = it;
	}
	if (!out)
		return fail(err, g->blocks[block].line, "default without out");
	if (strcmp(out->value, "allow") == 0)
		rs->out_allow = 1;
	else if (strcmp(out->value, "deny") == 0)
		rs->out_allow = 0;
	else
		return fail(err, out->line, "out must be allow or deny");
	rs->has_default = 1;
	return 0;
}

static int add_rule(struct ruleset *rs, const struct tconf *g, int block,
                    int allow, char *err) {
	const struct tconf_item *seen[K_COUNT] = {0};
	for (int i = 0; i < g->n; i++) {
		const struct tconf_item *it = &g->items[i];
		if (it->block != block)
			continue;
		int k = -1;
		for (int j = 0; j < K_COUNT; j++)
			if (strcmp(it->key, key_names[j]) == 0)
				k = j;
		if (k < 0)
			return fail(err, it->line, "unknown key %s", it->key);
		if (seen[k])
			return fail(err, it->line, "repeated key %s", it->key);
		if (it->quoted)
			return fail(err, it->line, "%s must not be quoted", it->key);
		seen[k] = it;
	}

	int line = g->blocks[block].line;
	if (rs->n == RULES_MAX)
		return fail(err, line, "more than %d rules", RULES_MAX);
	struct rule *r = &rs->r[rs->n];
	memset(r, 0, sizeof(*r));
	r->allow = allow;

	const struct tconf_item *it = seen[K_DIRECTION];
	if (!it)
		return fail(err, line, "missing direction");
	if (strcmp(it->value, "in") == 0)
		r->dir = DIR_IN;
	else if (strcmp(it->value, "out") == 0)
		r->dir = DIR_OUT;
	else
		return fail(err, it->line, "direction must be in or out");

	if ((it = seen[K_INTERFACE])) {
		if (!valid_ifname(it->value))
			return fail(err, it->line, "invalid interface: %s", it->value);
		snprintf(r->iface, sizeof(r->iface), "%s", it->value);
	}
	if ((it = seen[K_PROTOCOL]) && parse_protocol(r, it, err) < 0)
		return -1;
	if ((it = seen[K_PORT])) {
		if (!r->protos || (r->protos & ~(PROTO_TCP | PROTO_UDP)))
			return fail(err, it->line, "port requires protocol tcp or udp");
		if (parse_port(r, it, err) < 0)
			return -1;
	}
	if ((it = seen[K_FROM]) && parse_net(&r->from, it, err) < 0)
		return -1;
	if ((it = seen[K_TO]) && parse_net(&r->to, it, err) < 0)
		return -1;
	rs->n++;
	return 0;
}

int rules_add(struct ruleset *rs, const struct tconf *g,
              char err[RULES_ERR_MAX]) {
	for (int i = 0; i < g->n; i++)
		if (g->items[i].block < 0)
			return fail(err, g->items[i].line, "%s outside a block",
			            g->items[i].key);
	for (int b = 0; b < g->nblocks; b++) {
		const char *name = g->blocks[b].name;
		int r;
		if (strcmp(name, "default") == 0)
			r = add_default(rs, g, b, err);
		else if (strcmp(name, "allow") == 0)
			r = add_rule(rs, g, b, 1, err);
		else if (strcmp(name, "deny") == 0)
			r = add_rule(rs, g, b, 0, err);
		else
			r = fail(err, g->blocks[b].line, "unknown block %s", name);
		if (r < 0)
			return -1;
	}
	return 0;
}

int rules_expanded(const struct rule *r) {
	int protos = 0;
	for (unsigned int bit = PROTO_TCP; bit <= PROTO_ICMP; bit <<= 1)
		protos += (r->protos & bit) != 0;
	return (protos ? protos : 1) * (r->nports ? r->nports : 1);
}
