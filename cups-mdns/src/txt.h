/*
 * txt.h — Printer TXT record builder
 *
 * Builds the binary rdata for a DNS TXT record containing
 * all required AirPrint / IPP Everywhere metadata keys.
 */

#ifndef TXT_H
#define TXT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TXT_MAX_LEN 1200 // comfortably under 1300-octet mDNS limit
#define TXT_KV_MAX 64	 // max key=value pairs

// A single key=value entry for the TXT record
struct txt_kv {
	const char *key;
	const char *value; // if NULL, treated as boolean key (no '=')
};

/* Build TXT rdata from an array of kv pairs.
 * Returns the number of bytes written to 'out', or -1 on overflow. */
int txt_build(const struct txt_kv *kvs, int nkvs, uint8_t *out, size_t out_cap);

// ── Printer-specific helpers ───────────────────────────────────

// Maximum number of printers (parsed from IPP response)
#define CUPS_MAX_PRINTERS 32

// Per-printer metadata extracted from CUPS
struct cups_printer {
	char name[256];			   // CUPS printer-name → mDNS instance label
	char rp[256];			   // queue path, e.g. "printers/HP"
	char info[256];			   // printer-info
	char model[256];		   // printer-make-and-model
	char location[256];		   // printer-location
	char uuid[256];			   // printer-uuid (without urn:uuid: prefix)
	char pdl[512];			   // comma-separated MIME types
	char paper_max[128];	   // max paper size (short name)
	char paper_supported[512]; // supported sizes, comma-separated
	char paper_size[512];	   // sizes with dimensions, e.g. "A4:210x297mm"
	int state;				   // printer-state: 3=idle
	bool shared;			   // printer-is-shared
	bool color;				   // printer-color-supported
	bool duplex;			   // sides-supported includes two-sided
	unsigned int printer_type; // hex printer-type
};

/* Build a complete Printer TXT record for one printer.
 * 'port' is the IPP port (for 'adminurl' etc.)
 * Returns bytes written, or -1 on error. */
int cups_txt_build(const struct cups_printer *p, const char *hostname, int port, uint8_t *out, size_t out_cap);

/* Normalize a CUPS printer-name to a safe mDNS instance label.
 * Keeps [a-zA-Z0-9_], replaces other chars with '_', strips trailing '_'. */
void cups_name_normalize(char *out, const char *name, size_t outlen);

// Print printer details to stdout (used by daemon and print tool).
void cups_printer_print(const struct cups_printer *p, int index);

#endif // TXT_H
