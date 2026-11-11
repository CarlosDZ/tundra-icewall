/* Real traffic for the tests: a listener that answers, and a client that
 * says whether it got through. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TIMEOUT_MS 700

static int usage(void) {
	fprintf(stderr, "usage: talk listen tcp|udp <port>\n"
	                "       talk tcp|udp <address> <port>\n");
	return 2;
}

static int make(int udp, struct sockaddr_in *sa, const char *addr,
                const char *port) {
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = AF_INET;
	sa->sin_port = htons((uint16_t)atoi(port));
	if (addr && inet_pton(AF_INET, addr, &sa->sin_addr) != 1)
		return -1;
	return socket(AF_INET, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC, 0);
}

static int readable(int fd) {
	struct pollfd p = {.fd = fd, .events = POLLIN};
	return poll(&p, 1, TIMEOUT_MS) > 0;
}

static int serve(int udp, const char *port) {
	struct sockaddr_in sa;
	int one = 1, fd = make(udp, &sa, NULL, port);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	    (!udp && listen(fd, 16) < 0)) {
		perror("listen error");
		return 1;
	}
	for (;;) {
		char buf[16];
		if (udp) {
			struct sockaddr_in from;
			socklen_t len = sizeof(from);
			if (recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from,
			             &len) > 0)
				sendto(fd, "hi", 2, 0, (struct sockaddr *)&from, len);
		} else {
			int c = accept(fd, NULL, NULL);
			if (c >= 0) {
				if (write(c, "hi", 2) < 0)
					perror("write error");
				close(c);
			}
		}
	}
}

static int client(int udp, const char *addr, const char *port) {
	struct sockaddr_in sa;
	char buf[16];
	int fd = make(udp, &sa, addr, port);
	if (fd < 0)
		return usage();
	struct timeval tv = {0, TIMEOUT_MS * 1000};
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return 1;
	if (udp && send(fd, "yo", 2, 0) < 0)
		return 1;
	return readable(fd) && recv(fd, buf, sizeof(buf), 0) == 2 ? 0 : 1;
}

int main(int argc, char *argv[]) {
	if (argc == 4 && strcmp(argv[1], "listen") == 0)
		return serve(strcmp(argv[2], "udp") == 0, argv[3]);
	if (argc == 4 &&
	    (strcmp(argv[1], "tcp") == 0 || strcmp(argv[1], "udp") == 0))
		return client(strcmp(argv[1], "udp") == 0, argv[2], argv[3]);
	return usage();
}
