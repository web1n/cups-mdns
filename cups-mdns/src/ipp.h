/*
 * ipp.h — IPP / CUPS client
 *
 * Sends a CUPS-Get-Printers IPP request and parses the binary response
 * into a list of printer_t structs.
 */

#ifndef IPP_H
#define IPP_H

#include <stdint.h>
#include "txt.h" // for cups_printer

typedef enum {
	IPP_PRINTER_IDLE = 3,
	IPP_PRINTER_PROCESSING = 4,
	IPP_PRINTER_STOPPED = 5,
} ipp_printer_state_t;

static inline const char *ipp_state_name(int state) {
	switch (state) {
		case 3:
			return "idle";
		case 4:
			return "processing";
		case 5:
			return "stopped";
		default:
			return "unknown";
	}
}

/* Fetch the list of shared printers from a CUPS server.
 * Returns number of printers found (>=0), or -1 on error.
 * On success fills 'list' with up to CUPS_MAX_PRINTERS entries. */
int ipp_fetch_printers(const char *host, int port, int timeout_sec, struct cups_printer *list, int max_count);

#endif // IPP_H
