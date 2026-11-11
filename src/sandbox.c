#include "sandbox.h"

#include <linux/capability.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <wchar.h>

#define ALLOW(ctx, name, ...)                                                  \
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), __VA_ARGS__)

static int caps_reduce(void) {
	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2];

	if (syscall(SYS_capget, &hdr, data) < 0) {
		perror("capget error");
		return -1;
	}
	__u32 keep = data[0].permitted & (1u << CAP_NET_ADMIN);
	memset(data, 0, sizeof(data));
	data[0].permitted = keep;
	data[0].effective = keep;
	if (syscall(SYS_capset, &hdr, data) < 0) {
		perror("capset error");
		return -1;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
		perror("prctl error");
		return -1;
	}
	return 0;
}

/* glibc would fstat and ioctl stdout on its first write, and perror dups an
 * unoriented stderr: both are settled here so the filter needs none of it. */
static void stdio_settle(void) {
	static char out_buf[BUFSIZ];

	setvbuf(stdout, out_buf, isatty(STDOUT_FILENO) ? _IOLBF : _IOFBF,
	        sizeof(out_buf));
	fwide(stderr, -1);
}

static int filter_load(int nl_fd) {
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (ctx == NULL) {
		fprintf(stderr, "seccomp error: cannot create the filter\n");
		return -1;
	}

	int r =
	    seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS);

	if (r == 0)
		r = ALLOW(ctx, write, 1, SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO));
	if (r == 0)
		r = ALLOW(ctx, write, 1, SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
	if (r == 0)
		r = ALLOW(ctx, sendto, 1, SCMP_A0(SCMP_CMP_EQ, nl_fd));
	if (r == 0)
		r = ALLOW(ctx, recvfrom, 1, SCMP_A0(SCMP_CMP_EQ, nl_fd));
	if (r == 0)
		r = ALLOW(ctx, poll, 0);
	if (r == 0)
		r = ALLOW(ctx, ppoll, 0);
	if (r == 0)
		r = ALLOW(ctx, brk, 0);
	if (r == 0)
		r = ALLOW(ctx, mmap, 2, SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, 0),
		          SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_ANONYMOUS, MAP_ANONYMOUS));
	if (r == 0)
		r = ALLOW(ctx, mremap, 0);
	if (r == 0)
		r = ALLOW(ctx, munmap, 0);
	if (r == 0)
		r = ALLOW(ctx, exit_group, 0);
	if (r == 0)
		r = seccomp_load(ctx);

	seccomp_release(ctx);
	if (r < 0) {
		fprintf(stderr, "seccomp error: %s\n", strerror(-r));
		return -1;
	}
	return 0;
}

int sandbox_enter(int nl_fd) {
	stdio_settle();
	if (caps_reduce() < 0)
		return -1;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("prctl error");
		return -1;
	}
	return filter_load(nl_fd);
}
