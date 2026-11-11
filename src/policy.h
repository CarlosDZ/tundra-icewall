#ifndef TUNDRA_POLICY_H
#define TUNDRA_POLICY_H

#include "nfmsg.h"
#include "rules.h"

#define POLICY_TABLE "tundra-icewall"
#define POLICY_KERNEL_RULES_MAX 1024
#define POLICY_STATE_POLICY "policy"
#define POLICY_STATE_LOCKDOWN "lockdown"

/* The whole batch that replaces the table: fixed rules, then the ones of rs.
 * The sequence number of its last message, 0 if it does not fit. */
uint32_t policy_build(struct nfbuf *b, const struct ruleset *rs);

/* Only local traffic. */
uint32_t policy_lockdown(struct nfbuf *b);

/* The request for the table, to read its state back. */
uint32_t policy_query(struct nfbuf *b);

/* Kernel rules rs becomes, fixed ones aside. */
int policy_count(const struct ruleset *rs);

#endif
