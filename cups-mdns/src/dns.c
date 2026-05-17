/*
 * dns.c — DNS wire-format encode / decode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <errno.h>

#include "dns.h"

/* ═════════════════════════════════════════════════════════════════
 *  utility
 * ═════════════════════════════════════════════════════════════════ */

static uint16_t be16(uint16_t v) {
	return htons(v);
}
static uint16_t r16(const uint8_t *p) {
	return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t r32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void w16(uint8_t *p, uint16_t v) {
	p[0] = v >> 8;
	p[1] = v;
}
static void w32(uint8_t *p, uint32_t v) {
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

const char *dns_type_str(uint16_t type) {
	switch (type) {
		case DNS_TYPE_A:
			return "A";
		case DNS_TYPE_PTR:
			return "PTR";
		case DNS_TYPE_TXT:
			return "TXT";
		case DNS_TYPE_AAAA:
			return "AAAA";
		case DNS_TYPE_SRV:
			return "SRV";
		case DNS_TYPE_NSEC:
			return "NSEC";
		case DNS_TYPE_ANY:
			return "ANY";
		default:
			return "?";
	}
}

int dns_name_ends_with(const char *name, const char *suffix) {
	size_t nl = strlen(name), sl = strlen(suffix);
	if (sl > nl) return 0;
	return strcasecmp(name + nl - sl, suffix) == 0;
}

bool dns_name_is_reverse_v4(const char *name) {
	return dns_name_ends_with(name, ".in-addr.arpa");
}

bool dns_name_is_reverse_v6(const char *name) {
	return dns_name_ends_with(name, ".ip6.arpa");
}

/* ═════════════════════════════════════════════════════════════════
 *  packet builder
 * ═════════════════════════════════════════════════════════════════ */

void dns_builder_init(struct dns_builder *b, uint8_t *buf, size_t cap) {
	b->buf = buf;
	b->cap = cap;
	dns_builder_reset(b);
}

void dns_builder_reset(struct dns_builder *b) {
	b->pos = sizeof(struct dns_header);
	b->dnptr_idx = 0;
	b->dnptrs[b->dnptr_idx++] = (uint8_t *)b->buf;
	b->dnptrs[b->dnptr_idx] = NULL;
	memset(b->buf, 0, b->cap);
}

void dns_hdr_write(struct dns_builder *b, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
	struct dns_header *h = (struct dns_header *)b->buf;
	h->id = 0; // mDNS: always 0
	h->flags = be16(flags);
	h->qdcount = be16(qd);
	h->ancount = be16(an);
	h->nscount = be16(ns);
	h->arcount = be16(ar);
}

// ── name encoding with compression ──────────────────────────────

static int dns_name_encode(struct dns_builder *b, const char *name) {
	uint8_t *dst = b->buf + b->pos;
	int remain = (int)(b->cap - b->pos);
	if (remain <= 0) return -1;

	uint8_t **lastp = &b->dnptrs[(int)(sizeof(b->dnptrs) / sizeof(b->dnptrs[0])) - 1];

	int len = dn_comp(name, dst, remain, b->dnptrs, lastp);
	if (len < 0) {
		fprintf(stderr, "dns_name_encode: dn_comp failed for '%s'\n", name);
		return -1;
	}

	// advance dnptr index past newly added pointers
	while (b->dnptrs[b->dnptr_idx] && b->dnptr_idx < (int)(sizeof(b->dnptrs) / sizeof(b->dnptrs[0])) - 1)
		b->dnptr_idx++;
	b->dnptrs[b->dnptr_idx] = NULL;

	b->pos += len;
	return len;
}

int dns_question_add(struct dns_builder *b, const char *name, uint16_t type, bool unicast_reply) {
	int nlen = dns_name_encode(b, name);
	if (nlen < 0) return -1;

	if (b->pos + 4 > b->cap) return -1;
	w16(b->buf + b->pos, type);
	b->pos += 2;
	uint16_t class_val = DNS_CLASS_IN;
	if (unicast_reply) class_val |= DNS_CLASS_QU;
	w16(b->buf + b->pos, class_val);
	b->pos += 2;

	struct dns_header *h = (struct dns_header *)b->buf;
	h->qdcount = be16(be16(h->qdcount) + 1);
	return 0;
}

int dns_rr_add(struct dns_builder *b, const char *name, uint16_t type, uint32_t ttl, const uint8_t *rdata,
			   uint16_t rdlen, bool cache_flush) {
	int nlen = dns_name_encode(b, name);
	if (nlen < 0) return -1;

	if (b->pos + 10 + rdlen > b->cap) return -1;

	w16(b->buf + b->pos, type);
	b->pos += 2;
	uint16_t class_val = DNS_CLASS_IN;
	if (cache_flush) class_val |= DNS_CLASS_FLUSH;
	w16(b->buf + b->pos, class_val);
	b->pos += 2;
	w32(b->buf + b->pos, ttl);
	b->pos += 4;
	w16(b->buf + b->pos, rdlen);
	b->pos += 2;
	if (rdlen) {
		memcpy(b->buf + b->pos, rdata, rdlen);
		b->pos += rdlen;
	}

	struct dns_header *h = (struct dns_header *)b->buf;
	h->ancount = be16(be16(h->ancount) + 1);
	return 0;
}

int dns_a_add(struct dns_builder *b, const char *name, uint32_t ttl, uint32_t ip) {
	uint8_t rdata[4];
	uint32_t nip = htonl(ip);
	memcpy(rdata, &nip, 4);
	return dns_rr_add(b, name, DNS_TYPE_A, ttl, rdata, 4, true);
}

int dns_ptr_add(struct dns_builder *b, const char *name, uint32_t ttl, const char *target) {
	/* target is a domain name; we can't just use raw bytes.
	   We need to encode it inline.  Use a separate tiny builder trick.
	   Instead: build the rr manually, name-compressing the target. */

	int nlen = dns_name_encode(b, name);
	if (nlen < 0) return -1;

	if (b->pos + 10 > b->cap) return -1;

	w16(b->buf + b->pos, DNS_TYPE_PTR);
	b->pos += 2;
	w16(b->buf + b->pos, DNS_CLASS_IN);
	b->pos += 2;
	w32(b->buf + b->pos, ttl);
	b->pos += 4;

	// rdlength placeholder — we'll fix up after encoding target
	size_t rdlen_pos = b->pos;
	b->pos += 2;

	// encode target name (the PTR points here)
	int tlen = dns_name_encode(b, target);
	if (tlen < 0) {
		b->pos = rdlen_pos + 2; // rewind — best-effort
		return -1;
	}

	w16(b->buf + rdlen_pos, (uint16_t)tlen);

	struct dns_header *h = (struct dns_header *)b->buf;
	h->ancount = be16(be16(h->ancount) + 1);
	return 0;
}

int dns_srv_add(struct dns_builder *b, const char *name, uint32_t ttl, uint16_t pri, uint16_t weight, uint16_t port,
				const char *target) {
	int nlen = dns_name_encode(b, name);
	if (nlen < 0) return -1;

	if (b->pos + 10 > b->cap) return -1;

	w16(b->buf + b->pos, DNS_TYPE_SRV);
	b->pos += 2;
	w16(b->buf + b->pos, DNS_CLASS_IN | DNS_CLASS_FLUSH);
	b->pos += 2;
	w32(b->buf + b->pos, ttl);
	b->pos += 4;

	size_t rdlen_pos = b->pos;
	b->pos += 2;

	// SRV rdata: priority(2) + weight(2) + port(2) + target(variable)
	if (b->pos + 6 > b->cap) return -1;
	w16(b->buf + b->pos, pri);
	b->pos += 2;
	w16(b->buf + b->pos, weight);
	b->pos += 2;
	w16(b->buf + b->pos, port);
	b->pos += 2;

	int tlen = dns_name_encode(b, target);
	if (tlen < 0) return -1;

	w16(b->buf + rdlen_pos, (uint16_t)(6 + tlen));

	struct dns_header *h = (struct dns_header *)b->buf;
	h->ancount = be16(be16(h->ancount) + 1);
	return 0;
}

int dns_txt_add(struct dns_builder *b, const char *name, uint32_t ttl, const uint8_t *txt_data, uint16_t txt_len) {
	return dns_rr_add(b, name, DNS_TYPE_TXT, ttl, txt_data, txt_len, true);
}

int dns_nsec_add(struct dns_builder *b, const char *name, uint32_t ttl, const uint16_t *types, int ntypes) {
	/* Build NSEC rdata:
	 *   - Next Domain Name: same as owner name (no delegation)
	 *   - Type bitmaps */

	uint8_t rdata[512];
	int rpos = 0;

	// Encode "next domain name" = this name
	int nlen = dn_comp(name, rdata + rpos, (int)(sizeof(rdata) - rpos), NULL, NULL);
	if (nlen < 0) return -1;
	rpos += nlen;

	// Build type bitmap: group types by block number
	uint8_t blocks[32][32]; // up to 32 blocks of 32 bytes each
	int block_len[32];
	memset(blocks, 0, sizeof(blocks));
	memset(block_len, 0, sizeof(block_len));

	for (int i = 0; i < ntypes; i++) {
		int block = types[i] / 256;
		int bit = types[i] % 256;
		int byte_idx = bit / 8;
		int bit_idx = 7 - (bit % 8); // MSB-first within byte

		if (block < 32 && byte_idx < 32) {
			blocks[block][byte_idx] |= (1 << bit_idx);
			if (byte_idx + 1 > block_len[block]) block_len[block] = byte_idx + 1;
		}
	}

	for (int blk = 0; blk < 32; blk++) {
		if (block_len[blk] == 0) continue;
		if (rpos + 2 + block_len[blk] > (int)sizeof(rdata)) return -1;
		rdata[rpos++] = (uint8_t)blk;
		rdata[rpos++] = (uint8_t)block_len[blk];
		memcpy(rdata + rpos, blocks[blk], (size_t)block_len[blk]);
		rpos += block_len[blk];
	}

	return dns_rr_add(b, name, DNS_TYPE_NSEC, ttl, rdata, (uint16_t)rpos, true);
}

/* ═════════════════════════════════════════════════════════════════
 *  packet parser
 * ═════════════════════════════════════════════════════════════════ */

struct parse_ctx {
	const uint8_t *base;
	size_t blen;
	uint8_t *cur;
	int remain;
};

// decompress a name.  returns malloc'd string or NULL.  caller frees.
static char *parse_name(struct parse_ctx *ctx, uint8_t **ptr, int *rlen) {
	char name_buf[DNS_MAX_NAME];
	int used;

	used = dn_expand(ctx->base, ctx->base + ctx->blen, *ptr, name_buf, sizeof(name_buf));
	if (used < 0) return NULL;

	int nlen = 0;
	const uint8_t *s = *ptr;
	while (nlen < *rlen) {
		uint8_t b = s[nlen];
		if (b == 0) {
			nlen++;
			break;
		}
		if ((b & 0xC0) == 0xC0) {
			nlen += 2;
			break;
		}
		nlen += b + 1;
	}

	*ptr += nlen;
	*rlen -= nlen;
	return strdup(name_buf);
}

static bool parse_question(struct parse_ctx *ctx, void *user, dns_question_cb cb) {
	if (!cb) return true;

	char *name = parse_name(ctx, &ctx->cur, &ctx->remain);
	if (!name) return false;
	if (ctx->remain < 4) {
		free(name);
		return false;
	}

	uint16_t type = r16(ctx->cur);
	ctx->cur += 2;
	ctx->remain -= 2;
	uint16_t class_ = r16(ctx->cur);
	ctx->cur += 2;
	ctx->remain -= 2;

	bool keep_going = cb(name, type, class_, user);
	free(name);
	return keep_going;
}

static bool parse_rr(struct parse_ctx *ctx, void *user, dns_rr_cb cb) {
	if (!cb) {
		// skip: scan name, skip 10 + rdlen
		char *name = parse_name(ctx, &ctx->cur, &ctx->remain);
		if (!name) return false;
		free(name);
		if (ctx->remain < 10) return false;
		uint16_t rdlen = r16(ctx->cur + 8);
		if (ctx->remain < 10 + rdlen) return false;
		ctx->cur += 10 + rdlen;
		ctx->remain -= 10 + rdlen;
		return true;
	}

	char *name = parse_name(ctx, &ctx->cur, &ctx->remain);
	if (!name) return false;
	if (ctx->remain < 10) {
		free(name);
		return false;
	}

	uint16_t type = r16(ctx->cur);
	ctx->cur += 2;
	uint16_t class_ = r16(ctx->cur);
	ctx->cur += 2;
	uint32_t ttl = r32(ctx->cur);
	ctx->cur += 4;
	uint16_t rdlen = r16(ctx->cur);
	ctx->cur += 2;
	ctx->remain -= 10;

	if (rdlen > (uint16_t)ctx->remain) {
		free(name);
		return false;
	}

	const uint8_t *rdata = ctx->cur;
	ctx->cur += rdlen;
	ctx->remain -= rdlen;

	bool keep_going = cb(name, type, class_, ttl, rdata, rdlen, user);
	free(name);
	return keep_going;
}

int dns_packet_parse(const uint8_t *pkt, size_t len, struct dns_parse_callbacks *cb, void *user) {
	if (len < sizeof(struct dns_header)) return -1;

	const struct dns_header *h = (const struct dns_header *)pkt;

	struct parse_ctx ctx = {
		.base = pkt,
		.blen = len,
		.cur = (uint8_t *)(pkt + sizeof(struct dns_header)),
		.remain = (int)(len - sizeof(struct dns_header)),
	};

	uint16_t qd = r16((const uint8_t *)&h->qdcount);
	uint16_t an = r16((const uint8_t *)&h->ancount);
	uint16_t ns = r16((const uint8_t *)&h->nscount);
	uint16_t ar = r16((const uint8_t *)&h->arcount);

	for (uint16_t i = 0; i < qd; i++)
		if (!parse_question(&ctx, user, cb->on_question)) return 0;

	for (uint16_t i = 0; i < an; i++)
		if (!parse_rr(&ctx, user, cb->on_answer)) return 0;

	for (uint16_t i = 0; i < ns; i++)
		if (!parse_rr(&ctx, user, cb->on_authority)) return 0;

	for (uint16_t i = 0; i < ar; i++)
		if (!parse_rr(&ctx, user, cb->on_additional)) return 0;

	return 0;
}
