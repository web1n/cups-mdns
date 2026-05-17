/*
 * main.c — CUPS mDNS bridge
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

#include "mdns.h"
#include "ipp.h"
#include "txt.h"

/* ═════════════════════════════════════════════════════════════════
 *  config
 * ═════════════════════════════════════════════════════════════════ */

typedef struct {
	char cups_host[256];
	int cups_port;
	int interval_sec;
	int timeout_sec;
	char hostname[256];
	char ifname[64];
	bool debug;
	bool loopback;
} config_t;

/* ═════════════════════════════════════════════════════════════════
 *  helpers
 * ═════════════════════════════════════════════════════════════════ */

static volatile int g_running = 1;

static void on_signal(int sig) {
	(void)sig;
	g_running = 0;
}

// Parse IPv4 address (host byte order). Returns 0 on failure.
static uint32_t resolve_ip(const char *host) {
	struct in_addr a;
	if (inet_pton(AF_INET, host, &a) == 1) return ntohl(a.s_addr);
	return 0;
}

/* ═════════════════════════════════════════════════════════════════
 *  CLI
 * ═════════════════════════════════════════════════════════════════ */

static void print_usage(const char *prog) {
	fprintf(stderr,
			"Usage: %s --host <host> --port <port> [options]\n\n"
			"Required:\n"
			"  -H, --host <host>         CUPS server IPv4 address\n"
			"  -P, --port <port>         CUPS server port\n\n"
			"Options:\n"
			"  -n, --hostname <name>     mDNS hostname (default: cups-proxy)\n"
			"  -i, --interval <seconds>  Poll interval, 5..600 (default: 360)\n"
			"  -t, --timeout <seconds>   HTTP request timeout, 1..300 (default: 5)\n"
			"  -d, --debug               Verbose logging\n"
			"  -l, --loopback            Enable multicast loopback\n"
			"  -h, --help                Show this help\n",
			prog);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->interval_sec = 360;
	cfg->timeout_sec = 5;

	static struct option long_opts[] = {
		{"host", required_argument, 0, 'H'},	 {"port", required_argument, 0, 'P'},
		{"hostname", required_argument, 0, 'n'}, {"interval", required_argument, 0, 'i'},
		{"timeout", required_argument, 0, 't'},	 {"iface", required_argument, 0, 'I'},
		{"debug", no_argument, 0, 'd'},			 {"loopback", no_argument, 0, 'l'},
		{"help", no_argument, 0, 'h'},			 {0, 0, 0, 0}};

	int c;
	while ((c = getopt_long(argc, argv, "H:P:n:i:t:I:dlh", long_opts, NULL)) != -1) {
		switch (c) {
			case 'H':
				snprintf(cfg->cups_host, sizeof(cfg->cups_host), "%s", optarg);
				break;
			case 'P':
				cfg->cups_port = atoi(optarg);
				if (cfg->cups_port <= 0 || cfg->cups_port > 65535) {
					fprintf(stderr, "Invalid port: %s\n", optarg);
					return -1;
				}
				break;
			case 'n':
				snprintf(cfg->hostname, sizeof(cfg->hostname), "%s", optarg);
				break;
			case 'i':
				cfg->interval_sec = atoi(optarg);
				if (cfg->interval_sec < 5 || cfg->interval_sec > 600) {
					fprintf(stderr, "Invalid interval: %s\n", optarg);
					return -1;
				}
				break;
			case 't':
				cfg->timeout_sec = atoi(optarg);
				if (cfg->timeout_sec < 1 || cfg->timeout_sec > 300) {
					fprintf(stderr, "Invalid timeout: %s\n", optarg);
					return -1;
				}
				break;
			case 'I':
				snprintf(cfg->ifname, sizeof(cfg->ifname), "%s", optarg);
				break;
			case 'd':
				cfg->debug = true;
				break;
			case 'l':
				cfg->loopback = true;
				break;
			case 'h':
				print_usage(argv[0]);
				exit(0);
			default:
				return -1;
		}
	}

	if (cfg->cups_host[0] == '\0') {
		fprintf(stderr, "Error: --host is required\n");
		return -1;
	}
	if (!resolve_ip(cfg->cups_host)) {
		fprintf(stderr, "Error: --host must be a valid IPv4 address\n");
		return -1;
	}
	if (cfg->cups_port == 0) {
		fprintf(stderr, "Error: --port is required\n");
		return -1;
	}
	if (!cfg->hostname[0]) snprintf(cfg->hostname, sizeof(cfg->hostname), "cups-proxy");
	return 0;
}

/* ═════════════════════════════════════════════════════════════════
 *  main
 * ═════════════════════════════════════════════════════════════════ */

struct tracked_printer {
	char name[256];
	bool active;
};

// Simple FNV-1a hash for printer change detection
static uint64_t printer_list_hash(struct cups_printer *list, int n) {
	uint64_t h = 14695981039346656037ULL;
	for (int i = 0; i < n; i++) {
		struct cups_printer *p = &list[i];
		if (!p->shared || !p->name[0] || !p->rp[0]) continue;
		const char *fields[] = {p->name, p->rp, p->info, p->model, p->uuid, p->pdl, p->location};
		for (int j = 0; j < 7; j++)
			for (const char *s = fields[j]; s && *s; s++)
				h = (h ^ (uint64_t)(unsigned char)*s) * 1099511628211ULL;
		h ^= (uint64_t)p->state;
		h ^= (uint64_t)(p->shared ? 1 : 0);
		h ^= (uint64_t)(p->color ? 2 : 0);
		h ^= (uint64_t)(p->duplex ? 4 : 0);
		h ^= (uint64_t)p->printer_type;
		for (const char *s = p->paper_max; s && *s; s++)
			h = (h ^ (uint64_t)(unsigned char)*s) * 1099511628211ULL;
	}
	return h;
}

int main(int argc, char **argv) {
	config_t cfg;
	if (parse_args(argc, argv, &cfg) != 0) {
		print_usage(argv[0]);
		return 1;
	}

	/* Resolve CUPS host to IP — this IP is both for IPP queries
	   and for the mDNS A record (iOS connects here for printing). */
	uint32_t printer_ip = resolve_ip(cfg.cups_host);
	if (!printer_ip) {
		fprintf(stderr, "Error: cannot resolve %s\n", cfg.cups_host);
		return 1;
	}

	struct in_addr ip_disp = {.s_addr = htonl(printer_ip)};
	char ip_str[64];
	inet_ntop(AF_INET, &ip_disp, ip_str, sizeof(ip_str));

	printf("CUPS mDNS bridge\n");
	printf("  CUPS:    %s:%d\n", cfg.cups_host, cfg.cups_port);
	printf("  Printer IP: %s\n", ip_str);
	printf("  Hostname:   %s.local\n", cfg.hostname);
	printf("  Interval:   %ds\n\n", cfg.interval_sec);

	// Init mDNS with printer IP as the A record target
	struct mdns *mdns =
		mdns_create(cfg.hostname, cfg.ifname[0] ? cfg.ifname : NULL, printer_ip, cfg.debug, cfg.loopback);
	if (!mdns) {
		fprintf(stderr, "Fatal: mDNS init failed\n");
		return 1;
	}

	signal(SIGTERM, on_signal);
	signal(SIGINT, on_signal);
	signal(SIGPIPE, SIG_IGN);

	int mdns_fd_v = mdns_fd(mdns);
	uint64_t last_poll_ms = 0;
	uint64_t last_hash = 0;
	struct tracked_printer tracked[CUPS_MAX_PRINTERS];
	int n_tracked = 0;

	// Fire first poll after 2s, then every interval_sec
	{
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t now = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		last_poll_ms = now - (int64_t)cfg.interval_sec * 1000 + 2000;
	}

	printf("Running — Ctrl+C to stop.\n\n");

	while (g_running) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t now = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

		int timeout = mdns_next_timeout_ms(mdns);
		int64_t poll_in = (int64_t)cfg.interval_sec * 1000 - (int64_t)(now - last_poll_ms);
		if (poll_in < 0) poll_in = 0;
		if (timeout < 0 || (poll_in < timeout)) timeout = (int)poll_in;
		if (timeout < 0) timeout = 1000;

		struct pollfd fds[1] = {{.fd = mdns_fd_v, .events = POLLIN}};
		int ret = poll(fds, 1, timeout);
		if (ret < 0) {
			if (errno == EINTR) continue;
			break;
		}

		if (fds[0].revents & POLLIN) mdns_on_readable(mdns);
		mdns_on_timer(mdns);

		if ((int64_t)(now - last_poll_ms) >= (int64_t)cfg.interval_sec * 1000) {
			last_poll_ms = now;

			struct cups_printer list[CUPS_MAX_PRINTERS];
			int n = ipp_fetch_printers(cfg.cups_host, cfg.cups_port, cfg.timeout_sec, list, CUPS_MAX_PRINTERS);
			if (n < 0) {
				fprintf(stderr, "IPP fetch failed\n");
				continue;
			}

			uint64_t hash = printer_list_hash(list, n);
			if (hash == last_hash && !cfg.debug) continue;
			last_hash = hash;

			printf("Polled %s:%d, found %d printer(s)\n", cfg.cups_host, cfg.cups_port, n);

			for (int i = 0; i < n_tracked; i++)
				tracked[i].active = false;

			for (int i = 0; i < n; i++) {
				struct cups_printer *p = &list[i];
				if (!p->shared) continue;
				if (!p->name[0]) continue;
				if (!p->rp[0]) continue;

				char instance[256];
				cups_name_normalize(instance, p->name, sizeof(instance));

				uint8_t txt_buf[TXT_MAX_LEN];
				int txt_len = cups_txt_build(p, cfg.hostname, cfg.cups_port, txt_buf, sizeof(txt_buf));
				if (txt_len < 0) continue;

				int found = -1;
				for (int j = 0; j < n_tracked; j++)
					if (strcmp(tracked[j].name, instance) == 0) {
						found = j;
						break;
					}

				if (found < 0 && n_tracked < CUPS_MAX_PRINTERS) {
					snprintf(tracked[n_tracked].name, sizeof(tracked[0].name), "%s", instance);
					tracked[n_tracked].active = true;
					n_tracked++;
					printf("  + %s (%s)\n", instance, p->info[0] ? p->info : p->name);
					cups_printer_print(p, 0);
				} else if (found >= 0) {
					tracked[found].active = true;
				}

				mdns_service_set(mdns, instance, cfg.cups_port, txt_buf, txt_len);
			}

			for (int i = 0; i < n_tracked; i++) {
				if (!tracked[i].active) {
					printf("  - %s\n", tracked[i].name);
					mdns_service_remove(mdns, tracked[i].name);
					if (i < n_tracked - 1)
						memmove(&tracked[i], &tracked[i + 1], (size_t)(n_tracked - i - 1) * sizeof(tracked[0]));
					n_tracked--;
					i--;
				}
			}

			if (cfg.debug) printf("[main] poll: %d printers, %d tracked\n", n, n_tracked);
		}
	}

	printf("\nShutting down...\n");
	mdns_shutdown(mdns);
	mdns_destroy(mdns);
	printf("Done.\n");
	return 0;
}
