#include "files.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_SIZE_MAX (256 * 1024)
#define TEMPLATE "000-template.rules"

static int by_name(const void *a, const void *b) { return strcmp(a, b); }

static int wanted(const char *name) {
	size_t n = strlen(name);
	return n > 6 && n < FILES_NAME_MAX && name[0] != '.' &&
	       strcmp(name + n - 6, ".rules") == 0 && strcmp(name, TEMPLATE) != 0;
}

static ssize_t slurp(int dirfd, const char *name, char *buf, size_t size) {
	int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	struct stat st;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		errno = EINVAL;
		return -1;
	}
	size_t len = 0;
	for (;;) {
		ssize_t n = read(fd, buf + len, size - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		len += (size_t)n;
		if (len == size) {
			close(fd);
			errno = EFBIG;
			return -1;
		}
	}
	close(fd);
	return (ssize_t)len;
}

int files_load(const char *dir, struct ruleset *rs, char err[FILES_ERR_MAX]) {
	static char names[FILES_MAX][FILES_NAME_MAX];
	static char text[FILE_SIZE_MAX];
	static struct tconf g;
	int n = 0;

	rules_init(rs);
	DIR *d = opendir(dir);
	if (!d) {
		snprintf(err, FILES_ERR_MAX, "%.200s: %s", dir, strerror(errno));
		return -1;
	}
	for (struct dirent *e; (e = readdir(d));) {
		if (!wanted(e->d_name))
			continue;
		if (n == FILES_MAX) {
			closedir(d);
			snprintf(err, FILES_ERR_MAX, "%.200s: more than %d rule files", dir,
			         FILES_MAX);
			return -2;
		}
		snprintf(names[n++], FILES_NAME_MAX, "%s", e->d_name);
	}
	qsort(names, (size_t)n, sizeof(names[0]), by_name);

	int rc = 0;
	for (int i = 0; i < n && rc == 0; i++) {
		char why[RULES_ERR_MAX];
		ssize_t len = slurp(dirfd(d), names[i], text, sizeof(text));
		if (len < 0) {
			snprintf(err, FILES_ERR_MAX, "%.120s/%.63s: %.100s", dir, names[i],
			         strerror(errno));
			rc = -1;
		} else if (tconf_parse(text, (size_t)len, &g) < 0) {
			snprintf(err, FILES_ERR_MAX, "%.120s/%.63s: line %d: %.95s", dir,
			         names[i], g.err_line, g.err);
			rc = -2;
		} else if (rules_add(rs, &g, why) < 0) {
			snprintf(err, FILES_ERR_MAX, "%.120s/%.63s: %.130s", dir, names[i],
			         why);
			rc = -2;
		}
	}
	closedir(d);
	return rc;
}
