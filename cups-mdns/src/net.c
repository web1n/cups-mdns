/*
 * net.c — IPv4 multicast socket
 *
 * Create a UDP socket bound to 0.0.0.0:5353, join 224.0.0.251,
 * set up for mDNS-compliant send/recv.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "net.h"

int net_init(const char *ifname, bool loopback) {
	int fd, yes = 1;
	uint8_t ttl = 255;
	unsigned int ifindex = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("net_init: socket");
		return -1;
	}

	// Allow multiple listeners on the same port
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
		perror("net_init: SO_REUSEADDR");
		goto fail;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) < 0) {
		perror("net_init: SO_REUSEPORT");
		// non-fatal on older kernels
	}
#endif

	// Bind to mDNS port
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(5353),
		.sin_addr.s_addr = INADDR_ANY,
	};
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("net_init: bind");
		goto fail;
	}

	if (ifname) {
		ifindex = if_nametoindex(ifname);
		if (!ifindex) {
			fprintf(stderr, "net_init: unknown interface '%s'\n", ifname);
			goto fail;
		}
	}

	// Join multicast group on the specified interface
	struct ip_mreqn mreq = {
		.imr_multiaddr.s_addr = inet_addr("224.0.0.251"),
		.imr_ifindex = ifindex,
	};
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		perror("net_init: IP_ADD_MEMBERSHIP");
		goto fail;
	}

	// Multicast TTL = 255 (link-local only, but spec says 255)
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
		perror("net_init: IP_MULTICAST_TTL");
		// non-fatal
	}

	// Multicast loopback (disabled by default per RFC 6762)
	int loop = loopback ? 1 : 0;
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
		perror("net_init: IP_MULTICAST_LOOP");
	}

	// Set outgoing interface for multicast
	if (ifname) {
		struct ip_mreqn out_if = {.imr_ifindex = ifindex};
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &out_if, sizeof(out_if)) < 0) {
			perror("net_init: IP_MULTICAST_IF");
		}
	}

	// Enable receiving packet info (interface, destination address)
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0) {
		perror("net_init: IP_PKTINFO");
		// non-fatal
	}

	// Enable receiving TTL
	if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0) {
		perror("net_init: IP_RECVTTL");
		// non-fatal
	}

	return fd;

fail:
	close(fd);
	return -1;
}

int net_send_mcast(int fd, const uint8_t *pkt, size_t len) {
	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port = htons(5353),
		.sin_addr.s_addr = inet_addr("224.0.0.251"),
	};

	ssize_t n = sendto(fd, pkt, len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (n < 0) {
		perror("net_send_mcast");
		return -1;
	}
	return (int)n;
}

int net_send_unicast(int fd, const uint8_t *pkt, size_t len, const struct sockaddr_in *to) {
	struct sockaddr_in dst = *to;

	ssize_t n = sendto(fd, pkt, len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (n < 0) {
		perror("net_send_unicast");
		return -1;
	}
	return (int)n;
}

int net_recv(int fd, uint8_t *buf, size_t cap, struct sockaddr_in *from) {
	struct sockaddr_in src;
	socklen_t srclen = sizeof(src);

	ssize_t n = recvfrom(fd, buf, cap, 0, (struct sockaddr *)&src, &srclen);
	if (n < 0) {
		if (errno == EINTR) return 0;
		perror("net_recv");
		return -1;
	}

	// Ignore packets from ourselves (port 5353 check — loose heuristic)
	if (n > 0 && from) *from = src;

	return (int)n;
}

void net_close(int fd) {
	if (fd >= 0) close(fd);
}

uint32_t net_local_ip(int fd) {
	(void)fd;
	/* Get the local IP by connecting a UDP socket to a dummy address
	 * and reading the local address of the connection. */
	struct sockaddr_in dummy = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
	};
	inet_pton(AF_INET, "1.1.1.1", &dummy.sin_addr);

	// Use a temporary connected socket to find our IP
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) return 0;
	if (connect(s, (struct sockaddr *)&dummy, sizeof(dummy)) < 0) {
		close(s);
		// Fallback: try to get IP from interface
		return 0;
	}

	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	if (getsockname(s, (struct sockaddr *)&local, &len) < 0) {
		close(s);
		return 0;
	}
	close(s);

	return ntohl(local.sin_addr.s_addr);
}
