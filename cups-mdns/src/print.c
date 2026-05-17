/*
 * print.c — Standalone CUPS printer query tool
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "ipp.h"
#include "txt.h"

static void print_usage(const char *prog) {
	fprintf(stderr,
			"Usage: %s -H <host> -P <port> [-t <sec>]\n\n"
			"  -H, --host <host>     CUPS server IPv4 address\n"
			"  -P, --port <port>     CUPS server port\n"
			"  -t, --timeout <sec>   HTTP timeout (default: 5)\n"
			"  -h, --help            Show this help\n",
			prog);
}

int main(int argc, char **argv) {
	char host[256] = "";
	int port = 0, timeout = 5;

	static struct option long_opts[] = {{"host", required_argument, 0, 'H'},
										{"port", required_argument, 0, 'P'},
										{"timeout", required_argument, 0, 't'},
										{"help", no_argument, 0, 'h'},
										{0, 0, 0, 0}};

	int c;
	while ((c = getopt_long(argc, argv, "H:P:t:h", long_opts, NULL)) != -1) {
		switch (c) {
			case 'H':
				snprintf(host, sizeof(host), "%s", optarg);
				break;
			case 'P':
				port = atoi(optarg);
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			default:
				print_usage(argv[0]);
				return 1;
		}
	}

	if (!host[0] || !port) {
		print_usage(argv[0]);
		return 1;
	}

	printf("Querying CUPS server %s:%d ...\n\n", host, port);

	struct cups_printer list[CUPS_MAX_PRINTERS];
	int n = ipp_fetch_printers(host, port, timeout, list, CUPS_MAX_PRINTERS);

	if (n < 0) {
		fprintf(stderr, "IPP query failed\n");
		return 2;
	}
	if (n == 0) {
		printf("No printers found.\n");
		return 0;
	}

	printf("Found %d printer(s):\n\n", n);
	for (int i = 0; i < n; i++) {
		cups_printer_print(&list[i], i + 1);
		printf("\n");
	}

	return 0;
}
