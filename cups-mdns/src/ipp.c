/*
 * ipp.c — IPP / CUPS-Get-Printers client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <arpa/inet.h>

#include "ipp.h"

/* ═════════════════════════════════════════════════════════════════
 *  IPP binary helpers
 * ═════════════════════════════════════════════════════════════════ */

#define IPP_VERSION_20 0x0200
#define IPP_OP_CUPS_GET_PRINTERS 0x4002

#define IPP_TAG_OP_ATTRS 0x01
#define IPP_TAG_PRINTER_ATTRS 0x04
#define IPP_TAG_END 0x03

// value tags we care about
#define IPP_VTAG_INTEGER 0x21
#define IPP_VTAG_BOOLEAN 0x22
#define IPP_VTAG_ENUM 0x23
#define IPP_VTAG_STRING 0x41 // textWithoutLanguage
#define IPP_VTAG_NAME 0x42	 // nameWithoutLanguage
#define IPP_VTAG_KEYWORD 0x44
#define IPP_VTAG_URI 0x45
#define IPP_VTAG_CHARSET 0x47
#define IPP_VTAG_LANGUAGE 0x48
#define IPP_VTAG_MIME 0x49

static uint16_t read16(const uint8_t *p) {
	return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t read32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void write16(uint8_t *p, uint16_t v) {
	p[0] = v >> 8;
	p[1] = v;
}
static void write32(uint8_t *p, uint32_t v) {
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

// ── libcurl write callback ──────────────────────────────────────

struct chunk {
	uint8_t *data;
	size_t size;
};

static size_t write_cb(void *contents, size_t nmemb_size, size_t nmemb, void *user) {
	size_t real = nmemb_size * nmemb;
	struct chunk *c = (struct chunk *)user;
	uint8_t *p = realloc(c->data, c->size + real + 1);
	if (!p) return 0;
	c->data = p;
	memcpy(c->data + c->size, contents, real);
	c->size += real;
	c->data[c->size] = 0;
	return real;
}

/* ═════════════════════════════════════════════════════════════════
 *  IPP request builder
 * ═════════════════════════════════════════════════════════════════ */

static int ipp_append_attr(uint8_t *buf, size_t cap, size_t *pos, uint8_t tag, const char *name, const char *value) {
	size_t nl = strlen(name), vl = strlen(value);
	if (*pos + 5 + nl + vl > cap) return -1;

	buf[(*pos)++] = tag;
	write16(buf + *pos, (uint16_t)nl);
	*pos += 2;
	memcpy(buf + *pos, name, nl);
	*pos += nl;
	write16(buf + *pos, (uint16_t)vl);
	*pos += 2;
	memcpy(buf + *pos, value, vl);
	*pos += vl;
	return 0;
}

static int ipp_build_request(uint8_t *buf, size_t cap) {
	size_t pos = 0;

	write16(buf + pos, IPP_VERSION_20);
	pos += 2;
	write16(buf + pos, IPP_OP_CUPS_GET_PRINTERS);
	pos += 2;
	write32(buf + pos, 1);
	pos += 4;

	buf[pos++] = IPP_TAG_OP_ATTRS;

	ipp_append_attr(buf, cap, &pos, IPP_VTAG_CHARSET, "attributes-charset", "utf-8");
	ipp_append_attr(buf, cap, &pos, IPP_VTAG_LANGUAGE, "attributes-natural-language", "en-us");
	ipp_append_attr(buf, cap, &pos, IPP_VTAG_KEYWORD, "requested-attributes", "all");

	buf[pos++] = IPP_TAG_END;
	return (int)pos;
}

/* ═════════════════════════════════════════════════════════════════
 *  IPP response parser
 * ═════════════════════════════════════════════════════════════════ */

// attribute name → internal id mapping
enum attr_id {
	ATTR_NONE = 0,
	ATTR_DOCUMENT_FORMAT_SUPPORTED,
	ATTR_MEDIA_SUPPORTED,
	ATTR_PRINTER_COLOR_SUPPORTED,
	ATTR_INFO,
	ATTR_PRINTER_IS_SHARED,
	ATTR_LOCATION,
	ATTR_PRINTER_MAKE_AND_MODEL,
	ATTR_PRINTER_NAME,
	ATTR_PRINTER_STATE,
	ATTR_PRINTER_TYPE,
	ATTR_PRINTER_URI_SUPPORTED,
	ATTR_PRINTER_UUID,
	ATTR_SIDES_SUPPORTED,
	ATTR_COUNT
};

static const struct {
	const char *name;
	int id;
} attr_table[] = {
	{"document-format-supported", ATTR_DOCUMENT_FORMAT_SUPPORTED},
	{"media-supported", ATTR_MEDIA_SUPPORTED},
	{"printer-color-supported", ATTR_PRINTER_COLOR_SUPPORTED},
	{"printer-info", ATTR_INFO},
	{"printer-is-shared", ATTR_PRINTER_IS_SHARED},
	{"printer-location", ATTR_LOCATION},
	{"printer-make-and-model", ATTR_PRINTER_MAKE_AND_MODEL},
	{"printer-name", ATTR_PRINTER_NAME},
	{"printer-state", ATTR_PRINTER_STATE},
	{"printer-type", ATTR_PRINTER_TYPE},
	{"printer-uri-supported", ATTR_PRINTER_URI_SUPPORTED},
	{"printer-uuid", ATTR_PRINTER_UUID},
	{"sides-supported", ATTR_SIDES_SUPPORTED},
};

static int lookup_attr(const char *name, size_t nlen) {
	for (size_t i = 0; i < sizeof(attr_table) / sizeof(attr_table[0]); i++) {
		size_t alen = strlen(attr_table[i].name);
		if (nlen == alen && memcmp(name, attr_table[i].name, nlen) == 0) return attr_table[i].id;
	}
	return ATTR_NONE;
}

// strip urn:uuid: prefix
static const char *strip_uuid_prefix(const char *s, int *out_len) {
	if (strncasecmp(s, "urn:uuid:", 9) == 0) {
		*out_len -= 9;
		return s + 9;
	}
	return s;
}

// extract the queue path from a printer URI like ipp://host:631/printers/foo
static void extract_rp(const uint8_t *val, int vlen, char *out, size_t outlen) {
	char buf[512];
	int n = vlen < (int)sizeof(buf) - 1 ? vlen : (int)sizeof(buf) - 1;
	memcpy(buf, val, n);
	buf[n] = '\0';

	const char *p = strstr(buf, "://");
	if (!p) return;
	p = strchr(p + 3, '/');
	if (!p) {
		snprintf(out, outlen, "ipp/print");
		return;
	}
	while (*p == '/')
		p++;
	snprintf(out, outlen, "%s", p);
}

// check if sides-supported includes two-sided
static bool has_duplex(const uint8_t *val, int vlen) {
	char buf[128];
	int n = vlen < (int)sizeof(buf) - 1 ? vlen : (int)sizeof(buf) - 1;
	memcpy(buf, val, n);
	buf[n] = '\0';
	return strstr(buf, "two-sided") != NULL;
}

// append a MIME type to pdl string if it's known
static void pdl_append(char *pdl, size_t max, const char *mime) {
	static const char *known_types[] = {"application/pdf",
										"image/urf",
										"application/postscript",
										"application/vnd.cups-raster",
										"image/pwg-raster",
										"image/png",
										"image/jpeg",
										"image/tiff",
										"application/octet-stream",
										NULL};
	bool is_known = false;
	for (int i = 0; known_types[i]; i++)
		if (strcasecmp(mime, known_types[i]) == 0) {
			is_known = true;
			break;
		}
	if (!is_known) return;

	size_t cur = strlen(pdl);
	if (cur == 0) {
		strncat(pdl, mime, max - 1);
	} else {
		size_t need = cur + strlen(mime) + 2;
		if (need <= max) {
			pdl[cur] = ',';
			strcpy(pdl + cur + 1, mime);
		}
	}
}

// PWG media → short name + dimensions, rank-based best selection
static const char *media_short(const char *pwg, int *rank, const char **dims) {
	static const struct {
		const char *p;
		const char *s;
		const char *d;
		int r;
	} tab[] = {{"iso_a0_841x1189mm", "A0", "841x1189mm", -1},
			   {"iso_a1_594x841mm", "A1", "594x841mm", -1},
			   {"iso_a2_420x594mm", "A2", "420x594mm", -1},
			   {"iso_a3_297x420mm", "A3", "297x420mm", 0},
			   {"na_ledger_11x17in", "na-ledger", "11x17in", 1},
			   {"iso_b4_250x353mm", "B4", "250x353mm", 2},
			   {"na_legal_8.5x14in", "na-legal", "8.5x14in", 3},
			   {"jis_b4_257x364mm", "jis-b4", "257x364mm", 2},
			   {"iso_a4_210x297mm", "A4", "210x297mm", 4},
			   {"na_letter_8.5x11in", "na-letter", "8.5x11in", 5},
			   {"jis_b5_182x257mm", "jis-b5", "182x257mm", 6},
			   {"iso_b5_176x250mm", "B5", "176x250mm", 7},
			   {"iso_a5_148x210mm", "A5", "148x210mm", 8},
			   {"na_statement_5.5x8.5in", "na-statement", "5.5x8.5in", -1},
			   {"jis_b6_128x182mm", "jis-b6", "128x182mm", -1},
			   {"iso_a6_105x148mm", "A6", "105x148mm", -1},
			   {"om_postcard_100x148mm", "om-postcard", "100x148mm", -1},
			   {"na_index-4x6_4x6in", "na-index-4x6", "4x6in", -1},
			   {"na_index-3x5_3x5in", "na-index-3x5", "3x5in", -1},
			   {"om_env-dl_110x220mm", "om-env-dl", "110x220mm", -1},
			   {"om_env-c6_114x162mm", "om-env-c6", "114x162mm", -1},
			   {"om_env-chou3_120x235mm", "om-env-chou3", "120x235mm", -1},
			   {"om_env-chou4_90x205mm", "om-env-chou4", "90x205mm", -1},
			   {NULL, NULL, NULL, 999}};
	for (int i = 0; tab[i].p; i++)
		if (strcmp(pwg, tab[i].p) == 0) {
			*rank = tab[i].r;
			if (dims) *dims = tab[i].d;
			return tab[i].s;
		}
	*rank = 999;
	if (dims) *dims = NULL;
	return NULL;
}

// ── main parsing ────────────────────────────────────────────────

static void reset_pending(struct cups_printer *p) {
	memset(p, 0, sizeof(*p));
	p->state = IPP_PRINTER_IDLE;
	p->shared = true;
}

static void set_printer_uuid(struct cups_printer *p, const uint8_t *val, uint16_t val_len) {
	int ulen = (int)val_len;
	const char *u = strip_uuid_prefix((const char *)val, &ulen);
	snprintf(p->uuid, sizeof(p->uuid), "%.*s", ulen, u);
}

static void append_printer_media(struct cups_printer *p, const uint8_t *val, uint16_t val_len) {
	char buf[128];
	int n = (int)val_len < (int)sizeof(buf) - 1 ? (int)val_len : (int)sizeof(buf) - 1;
	memcpy(buf, val, n);
	buf[n] = '\0';

	int rank;
	const char *dims;
	const char *short_name = media_short(buf, &rank, &dims);
	if (!short_name) return;

	int have_rank;
	media_short(p->paper_max, &have_rank, NULL);
	if (rank < have_rank) snprintf(p->paper_max, sizeof(p->paper_max), "%s", short_name);

	size_t slen = strlen(p->paper_supported);
	if (slen > 0 && slen < sizeof(p->paper_supported) - strlen(short_name) - 2) {
		strcat(p->paper_supported, ",");
		strcat(p->paper_supported, short_name);
	} else if (slen == 0) {
		snprintf(p->paper_supported, sizeof(p->paper_supported), "%s", short_name);
	}

	size_t plen = strlen(p->paper_size);
	if (plen > 0 && dims && plen < sizeof(p->paper_size) - strlen(short_name) - strlen(dims) - 3) {
		strcat(p->paper_size, ",");
		strcat(p->paper_size, short_name);
		strcat(p->paper_size, ":");
		strcat(p->paper_size, dims);
	} else if (plen == 0) {
		if (dims) {
			snprintf(p->paper_size, sizeof(p->paper_size), "%s:%s", short_name, dims);
		} else {
			snprintf(p->paper_size, sizeof(p->paper_size), "%s", short_name);
		}
	}
}

static void append_document_format(struct cups_printer *p, const uint8_t *val, uint16_t val_len) {
	char mime[128];
	int n = (int)val_len < (int)sizeof(mime) - 1 ? (int)val_len : (int)sizeof(mime) - 1;
	memcpy(mime, val, n);
	mime[n] = '\0';
	pdl_append(p->pdl, sizeof(p->pdl), mime);
}

static int parse_ipp_response(const uint8_t *data, size_t len, struct cups_printer *list, int max_count) {
	if (!data || len < 8) return -1;

	uint16_t status = read16(data + 2);
	if (status != 0x0000) {
		fprintf(stderr, "IPP error status: 0x%04X\n", status);
		return -1;
	}

	int count = 0;
	struct cups_printer pending;
	struct cups_printer *cur = NULL;

	reset_pending(&pending);

	size_t pos = 8;
	const char *cur_attr_name = NULL;
	size_t cur_attr_namelen = 0;

	while (pos < len) {
		uint8_t tag = data[pos];

		if (tag < 0x10) {
			if (tag == IPP_TAG_END) break;
			if (tag == IPP_TAG_PRINTER_ATTRS) {
				reset_pending(&pending);
				cur = NULL;
				cur_attr_name = NULL;
				cur_attr_namelen = 0;
			}
			pos++;
			continue;
		}

		if (pos + 3 > len) break;
		size_t name_len = read16(data + pos + 1);
		if (pos + 3 + name_len + 2 > len) break;
		size_t val_len = read16(data + pos + 3 + name_len);

		const uint8_t *name_ptr = data + pos + 3;
		const uint8_t *val_ptr = data + pos + 3 + name_len + 2;

		if (pos + 3 + name_len + 2 + val_len > len) break;

		pos += 3 + name_len + 2 + val_len;

		if (name_len > 0) {
			cur_attr_name = (const char *)name_ptr;
			cur_attr_namelen = name_len;
		}
		if (!cur_attr_name) continue;

		int aid = lookup_attr(cur_attr_name, cur_attr_namelen);
		struct cups_printer *dst = cur ? cur : &pending;

		switch (aid) {
			case ATTR_PRINTER_NAME:
				if (count < max_count) {
					cur = &list[count++];
					*cur = pending;
					snprintf(cur->name, sizeof(cur->name), "%.*s", (int)val_len, (const char *)val_ptr);
				} else {
					cur = NULL;
				}
				break;

			case ATTR_PRINTER_STATE:
				if (val_len >= 4) dst->state = (int)read32(val_ptr);
				break;

			case ATTR_PRINTER_IS_SHARED:
				if (val_len >= 1) dst->shared = val_ptr[0];
				break;

			case ATTR_PRINTER_COLOR_SUPPORTED:
				if (val_len >= 1) dst->color = val_ptr[0];
				break;

			case ATTR_PRINTER_TYPE:
				if (val_len >= 4) dst->printer_type = read32(val_ptr);
				break;

			case ATTR_SIDES_SUPPORTED:
				if (val_len > 0) dst->duplex = has_duplex(val_ptr, (int)val_len);
				break;

			case ATTR_PRINTER_URI_SUPPORTED:
				extract_rp(val_ptr, (int)val_len, dst->rp, sizeof(dst->rp));
				break;

			case ATTR_PRINTER_UUID:
				set_printer_uuid(dst, val_ptr, val_len);
				break;

			case ATTR_INFO:
				snprintf(dst->info, sizeof(dst->info), "%.*s", (int)val_len, (const char *)val_ptr);
				break;

			case ATTR_LOCATION:
				snprintf(dst->location, sizeof(dst->location), "%.*s", (int)val_len, (const char *)val_ptr);
				break;

			case ATTR_PRINTER_MAKE_AND_MODEL:
				snprintf(dst->model, sizeof(dst->model), "%.*s", (int)val_len, (const char *)val_ptr);
				break;

			case ATTR_MEDIA_SUPPORTED:
				append_printer_media(dst, val_ptr, val_len);
				break;

			case ATTR_DOCUMENT_FORMAT_SUPPORTED:
				append_document_format(dst, val_ptr, val_len);
				break;

			default:
				break;
		}
	}

	return count;
}

/* ═════════════════════════════════════════════════════════════════
 *  public API
 * ═════════════════════════════════════════════════════════════════ */

int ipp_fetch_printers(const char *host, int port, int timeout_sec, struct cups_printer *list, int max_count) {
	CURL *curl = curl_easy_init();
	if (!curl) return -1;

	char url[512];
	snprintf(url, sizeof(url), "http://%s:%d/", host, port);

	uint8_t req[2048];
	int req_len = ipp_build_request(req, sizeof(req));
	if (req_len < 0) {
		curl_easy_cleanup(curl);
		return -1;
	}

	struct chunk c = {NULL, 0};

	struct curl_slist *hdrs = NULL;
	hdrs = curl_slist_append(hdrs, "Content-Type: application/ipp");

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)req_len);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &c);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_sec);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)timeout_sec);

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	int n = -1;
	if (res == CURLE_OK && http_code == 200) {
		n = parse_ipp_response(c.data, c.size, list, max_count);
		if (n < 0) fprintf(stderr, "IPP parse error\n");
	} else {
		fprintf(stderr, "IPP HTTP error: curl=%d (%s) http=%ld\n", (int)res, curl_easy_strerror(res), http_code);
	}

	free(c.data);
	return n;
}
