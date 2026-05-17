/*
 * txt.c — Printer TXT record builder
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "txt.h"
#include "ipp.h"

static const char *state_str(int state) {
	switch (state) {
		case IPP_PRINTER_IDLE:
			return "idle";
		case IPP_PRINTER_PROCESSING:
			return "processing";
		case IPP_PRINTER_STOPPED:
			return "stopped";
		default:
			return "unknown";
	}
}

// ── generic TXT builder ──────────────────────────────────────────

int txt_build(const struct txt_kv *kvs, int nkvs, uint8_t *out, size_t out_cap) {
	size_t pos = 0;

	for (int i = 0; i < nkvs; i++) {
		const char *key = kvs[i].key;
		const char *val = kvs[i].value;

		char item[256];
		int item_len;

		if (val && *val) item_len = snprintf(item, sizeof(item), "%s=%s", key, val);
		else item_len = snprintf(item, sizeof(item), "%s", key);

		if (item_len < 0 || item_len > 255) continue;

		if (pos + 1 + (size_t)item_len > out_cap) return -1;

		out[pos++] = (uint8_t)item_len;
		memcpy(out + pos, item, (size_t)item_len);
		pos += (size_t)item_len;
	}

	return (int)pos;
}

// ── printer name normalization ───────────────────────────────────

void cups_name_normalize(char *out, const char *name, size_t outlen) {
	if (!out || outlen == 0) return;
	if (!name || !*name) {
		snprintf(out, outlen, "UnknownPrinter");
		return;
	}

	size_t j = 0;
	bool last_invalid = true;
	const size_t max_label = outlen > 0 ? outlen - 1 : 0;

	for (size_t i = 0; name[i] && j < max_label && j < 63; i++) {
		unsigned char c = (unsigned char)name[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			out[j++] = (char)c;
			last_invalid = false;
		} else if (!last_invalid && j < max_label && j < 63) {
			out[j++] = '_';
			last_invalid = true;
		}
	}

	// trim trailing underscores
	while (j > 0 && out[j - 1] == '_')
		j--;
	out[j] = '\0';

	if (j == 0) snprintf(out, outlen, "UnknownPrinter");
}

int cups_txt_build(const struct cups_printer *p, const char *hostname, int port, uint8_t *out, size_t out_cap) {
	struct txt_kv kvs[TXT_KV_MAX];
	int n = 0;

	// Use CUPS printer-info as both note and ty
	const char *info = p->info[0] ? p->info : p->name;

	kvs[n++] = (struct txt_kv){"txtvers", "1"};
	kvs[n++] = (struct txt_kv){"qtotal", "1"};
	kvs[n++] = (struct txt_kv){"rp", p->rp[0] ? p->rp : "ipp/print"};

	// ty must be within first 400 octets — put it early
	const char *ty = p->model[0] ? p->model : info;
	kvs[n++] = (struct txt_kv){"ty", ty};

	kvs[n++] = (struct txt_kv){"note", info};

	// product: format "(Model Name)"
	char product[280];
	snprintf(product, sizeof(product), "(%s)", ty);
	kvs[n++] = (struct txt_kv){"product", product};

	if (p->pdl[0]) kvs[n++] = (struct txt_kv){"pdl", p->pdl};
	else kvs[n++] = (struct txt_kv){"pdl", "application/pdf,image/urf"};

	// ── URF ──
	kvs[n++] = (struct txt_kv){"URF", "DM3"};
	kvs[n++] = (struct txt_kv){"Transparent", "T"};

	kvs[n++] = (struct txt_kv){"Color", p->color ? "T" : "F"};
	kvs[n++] = (struct txt_kv){"Duplex", p->duplex ? "T" : "F"};

	if (p->paper_max[0]) kvs[n++] = (struct txt_kv){"PaperMax", p->paper_max};
	if (p->paper_size[0]) kvs[n++] = (struct txt_kv){"PaperSize", p->paper_size};
	if (p->paper_supported[0]) kvs[n++] = (struct txt_kv){"PaperSizeSupported", p->paper_supported};

	kvs[n++] = (struct txt_kv){"printer-state", "3"};

	char ptype[16];
	snprintf(ptype, sizeof(ptype), "0x%X", p->printer_type ? p->printer_type : 0x0480FFFCu);
	kvs[n++] = (struct txt_kv){"printer-type", ptype};

	if (p->uuid[0]) kvs[n++] = (struct txt_kv){"UUID", p->uuid};

	if (p->location[0]) kvs[n++] = (struct txt_kv){"location", p->location};

	kvs[n++] = (struct txt_kv){"air", "none"};

	char adminurl[512];
	snprintf(adminurl, sizeof(adminurl), "http://%s.local:%d/printers/%s", hostname, port, p->name);
	kvs[n++] = (struct txt_kv){"adminurl", adminurl};

	return txt_build(kvs, n, out, out_cap);
}

void cups_printer_print(const struct cups_printer *p, int index) {
	if (index > 0) printf("  %d. %s\n", index, p->name);
	if (p->info[0]) printf("     Info:        %s\n", p->info);
	if (p->model[0]) printf("     Model:       %s\n", p->model);
	if (p->location[0]) printf("     Location:    %s\n", p->location);
	if (p->rp[0]) printf("     Queue:       %s\n", p->rp);
	printf("     State:       %s\n", state_str(p->state));
	printf("     Shared:      %s\n", p->shared ? "yes" : "no");
	printf("     Color:       %s\n", p->color ? "yes" : "no");
	printf("     Duplex:      %s\n", p->duplex ? "yes" : "no");
	printf("     PrinterType: 0x%X\n", p->printer_type);
	if (p->paper_max[0]) printf("     PaperMax:    %s\n", p->paper_max);
	if (p->paper_size[0]) printf("     PaperSize:   %s\n", p->paper_size);
	if (p->paper_supported[0]) printf("     PaperSupp:   %s\n", p->paper_supported);
	if (p->uuid[0]) printf("     UUID:        %s\n", p->uuid);
	if (p->pdl[0]) printf("     PDL:         %s\n", p->pdl);
}
