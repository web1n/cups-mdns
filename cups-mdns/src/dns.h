/*
 * dns.h — DNS wire-format primitives for mDNS
 *
 * Uses dn_comp / dn_expand from libresolv for name (de)compression.
 *
 * mDNS note: packet id MUST be 0. CLASS bit 15 means:
 *   Question:  unicast-response desired
 *   RR:        cache-flush
 */

#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ── mDNS constants ───────────────────────────────────────────────

#define MCAST_ADDR "224.0.0.251"
#define MCAST_PORT 5353

// DNS types
#define DNS_TYPE_A 0x0001
#define DNS_TYPE_PTR 0x000C
#define DNS_TYPE_TXT 0x0010
#define DNS_TYPE_AAAA 0x001C
#define DNS_TYPE_SRV 0x0021
#define DNS_TYPE_NSEC 0x002F
#define DNS_TYPE_ANY 0x00FF

// DNS classes
#define DNS_CLASS_IN 0x0001
#define DNS_CLASS_FLUSH 0x8000 // cache-flush bit (RR only)
#define DNS_CLASS_QU 0x8000	   // unicast-response bit (question only)

// mDNS flags
#define DNS_FLAG_QR 0x8000 // response
#define DNS_FLAG_AA 0x0400 // authoritative answer

// Max packet sizes
#define DNS_MAX_NAME 256
#define DNS_MAX_PKT 1500 // avoid IP fragmentation

// ── on-wire structures (packed) ───────────────────────────────────

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

struct dns_srv_data {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
} __attribute__((packed));

// ── packet builder ───────────────────────────────────────────────

struct dns_builder {
	uint8_t *buf;
	size_t cap;
	size_t pos;			 // next write position
	uint8_t *dnptrs[64]; // compression pointer table
	int dnptr_idx;
};

void dns_builder_init(struct dns_builder *b, uint8_t *buf, size_t cap);
void dns_builder_reset(struct dns_builder *b);

// Write DNS header — always id=0 for mDNS
void dns_hdr_write(struct dns_builder *b, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar);

// Append a question.  unicast_reply sets the QU bit in CLASS.
int dns_question_add(struct dns_builder *b, const char *name, uint16_t type, bool unicast_reply);

// Append a resource record.  cache_flush sets the flush bit in CLASS.
int dns_rr_add(struct dns_builder *b, const char *name, uint16_t type, uint32_t ttl, const uint8_t *rdata,
			   uint16_t rdlen, bool cache_flush);

// Convenience: append A/PTR/SRV/TXT records
int dns_a_add(struct dns_builder *b, const char *name, uint32_t ttl, uint32_t ip);
int dns_ptr_add(struct dns_builder *b, const char *name, uint32_t ttl, const char *target);
int dns_srv_add(struct dns_builder *b, const char *name, uint32_t ttl, uint16_t pri, uint16_t weight, uint16_t port,
				const char *target);
int dns_txt_add(struct dns_builder *b, const char *name, uint32_t ttl, const uint8_t *txt_data, uint16_t txt_len);

// Append NSEC record: "this name has these types, no others"
int dns_nsec_add(struct dns_builder *b, const char *name, uint32_t ttl, const uint16_t *types, int ntypes);

// ── packet parser ────────────────────────────────────────────────

/* Callbacks for each section element encountered during parsing.
   Return false to stop parsing early. */
typedef bool (*dns_question_cb)(const char *name, uint16_t type, uint16_t class_, void *user);
typedef bool (*dns_rr_cb)(const char *name, uint16_t type, uint16_t class_, uint32_t ttl, const uint8_t *rdata,
						  uint16_t rdlen, void *user);

struct dns_parse_callbacks {
	dns_question_cb on_question;
	dns_rr_cb on_answer;
	dns_rr_cb on_authority;
	dns_rr_cb on_additional;
};

// Parse a complete DNS packet.  Returns 0 on success, -1 on error.
int dns_packet_parse(const uint8_t *pkt, size_t len, struct dns_parse_callbacks *cb, void *user);

// Return a human-readable type string ("A", "PTR", …)
const char *dns_type_str(uint16_t type);

// name helpers
int dns_name_ends_with(const char *name, const char *suffix);
bool dns_name_is_reverse_v4(const char *name);
bool dns_name_is_reverse_v6(const char *name);

#endif // DNS_H
