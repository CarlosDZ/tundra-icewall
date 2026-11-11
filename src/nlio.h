#ifndef TUNDRA_NLIO_H
#define TUNDRA_NLIO_H

#include <stddef.h>
#include <stdint.h>

#define NLIO_TIMEOUT_MS 5000
#define NLIO_STATE_MAX 32

int nlio_open(size_t sndbuf);

/* Sends a batch, first and last being the sequence numbers of its first and
 * last messages. 0 when the kernel took it whole; -1 with errno set to what
 * it answered. */
int nlio_commit(int fd, const unsigned char *data, size_t len, uint32_t first,
                uint32_t last);

/* The user data of the table: 1 with it in state, 0 when there is no table,
 * -1 on failure. */
int nlio_table_state(int fd, const unsigned char *data, size_t len,
                     uint32_t seq, char state[NLIO_STATE_MAX]);

#endif
