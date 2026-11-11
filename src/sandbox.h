#ifndef TUNDRA_SANDBOX_H
#define TUNDRA_SANDBOX_H

/* ADR-031: keeps only CAP_NET_ADMIN and loads a seccomp filter that leaves
 * the netlink socket and the two output streams. Nothing is opened or read
 * after it. */
int sandbox_enter(int nl_fd);

#endif
