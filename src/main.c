#include "files.h"
#include "nlio.h"
#include "policy.h"
#include "sandbox.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define EXIT_OK 0
#define EXIT_FAIL 1
#define EXIT_USAGE 2

#define BATCH_MAX (1024 * 1024)
#define FIRST_SEQ 1

static unsigned char batch[BATCH_MAX];
static struct ruleset rules;

static void usage(FILE *f) {
	fprintf(f, "usage: tundra-icewall check [directory]\n"
	           "       tundra-icewall load [directory]\n"
	           "       tundra-icewall boot [directory]\n"
	           "       tundra-icewall lockdown\n"
	           "       tundra-icewall status\n"
	           "       tundra-icewall --version\n");
}

/* 0, or the exit code the failure deserves. */
static int read_rules(const char *dir) {
	char err[FILES_ERR_MAX];
	int r = files_load(dir, &rules, err);
	if (r < 0) {
		fprintf(stderr, "%s\n", err);
		return r == -2 ? EXIT_USAGE : EXIT_FAIL;
	}
	int n = policy_count(&rules);
	if (n > POLICY_KERNEL_RULES_MAX) {
		fprintf(stderr, "%s: the rules expand to %d, more than %d\n", dir, n,
		        POLICY_KERNEL_RULES_MAX);
		return EXIT_USAGE;
	}
	return 0;
}

static int open_kernel(void) {
	int fd = nlio_open(BATCH_MAX);
	if (fd < 0) {
		perror("netlink error");
		return -1;
	}
	if (sandbox_enter(fd) < 0)
		return -1;
	return fd;
}

static int commit(int fd, int lockdown) {
	struct nfbuf b;
	nfbuf_init(&b, batch, sizeof(batch), FIRST_SEQ);
	uint32_t last = lockdown ? policy_lockdown(&b) : policy_build(&b, &rules);
	if (!last) {
		fprintf(stderr, "the policy does not fit in a transaction\n");
		return -1;
	}
	if (nlio_commit(fd, b.data, b.len, FIRST_SEQ, last) < 0) {
		fprintf(stderr, "the kernel refused the %s: %s\n",
		        lockdown ? "lockdown" : "policy", strerror(errno));
		return -1;
	}
	return 0;
}

static int cmd_check(const char *dir) {
	int code = read_rules(dir);
	if (code)
		return code;
	printf("%s: %d rules, out %s\n", dir, rules.n,
	       rules.has_default && rules.out_allow ? "allowed" : "denied");
	return EXIT_OK;
}

/* A failure at boot leaves the lockdown, never an older or a looser policy:
 * there is none to keep. */
static int cmd_load(const char *dir, int boot) {
	int code = read_rules(dir);
	int fd = open_kernel();
	if (fd < 0)
		return EXIT_FAIL;
	if (!code && commit(fd, 0) < 0)
		code = EXIT_FAIL;
	if (!code) {
		printf("policy loaded: %d rules, out %s\n", rules.n,
		       rules.has_default && rules.out_allow ? "allowed" : "denied");
		return EXIT_OK;
	}
	if (!boot) {
		fprintf(stderr, "the policy in the kernel is left as it was\n");
		return code;
	}
	if (commit(fd, 1) == 0)
		fprintf(stderr, "lockdown loaded: only local traffic\n");
	return code;
}

static int cmd_lockdown(void) {
	int fd = open_kernel();
	if (fd < 0 || commit(fd, 1) < 0)
		return EXIT_FAIL;
	printf("lockdown loaded: only local traffic\n");
	return EXIT_OK;
}

static int cmd_status(void) {
	char state[NLIO_STATE_MAX];
	struct nfbuf b;
	int fd = open_kernel();
	if (fd < 0)
		return EXIT_FAIL;
	nfbuf_init(&b, batch, sizeof(batch), FIRST_SEQ);
	uint32_t seq = policy_query(&b);
	int r = nlio_table_state(fd, b.data, b.len, seq, state);
	if (r < 0) {
		fprintf(stderr, "cannot read the table: %s\n", strerror(errno));
		return EXIT_FAIL;
	}
	if (r == 0)
		printf("none\n");
	else if (strcmp(state, POLICY_STATE_POLICY) == 0 ||
	         strcmp(state, POLICY_STATE_LOCKDOWN) == 0)
		printf("%s\n", state);
	else
		printf("unknown\n");
	return EXIT_OK;
}

int main(int argc, char *argv[]) {
	const char *cmd = argc > 1 ? argv[1] : "";
	const char *dir = argc > 2 ? argv[2] : TUNDRA_ICEWALL_DIR;
	int takes_dir = strcmp(cmd, "check") == 0 || strcmp(cmd, "load") == 0 ||
	                strcmp(cmd, "boot") == 0;

	if (strcmp(cmd, "--version") == 0 && argc == 2) {
		printf("tundra-icewall %s\n", TUNDRA_ICEWALL_VERSION);
		return EXIT_OK;
	}
	if ((strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) && argc == 2) {
		usage(stdout);
		return EXIT_OK;
	}
	if (argc < 2 || argc > (takes_dir ? 3 : 2)) {
		usage(stderr);
		return EXIT_USAGE;
	}
	if (strcmp(cmd, "check") == 0)
		return cmd_check(dir);
	if (strcmp(cmd, "load") == 0)
		return cmd_load(dir, 0);
	if (strcmp(cmd, "boot") == 0)
		return cmd_load(dir, 1);
	if (strcmp(cmd, "lockdown") == 0)
		return cmd_lockdown();
	if (strcmp(cmd, "status") == 0)
		return cmd_status();
	usage(stderr);
	return EXIT_USAGE;
}
