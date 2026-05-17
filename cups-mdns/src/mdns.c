/*
 * mdns.c — mDNS responder state machine
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include "mdns.h"
#include "dns.h"
#include "net.h"

#define ANNOUNCE_TTL (75 * 60)
#define PROBE_INTERVAL_MS 250
#define WAIT_INTERVAL_MS 250
#define ANNOUNCE_GAP_MS 2000
#define REANNOUNCE_FACTOR 80

#define MAX_SERVICES 32
#define SERVICE_TYPE "_ipp._tcp.local"
#define SUBTYPE_NAME "_universal._sub._ipp._tcp.local"
#define DNS_SD_NAME "_services._dns-sd._udp.local"

/* ═════════════════════════════════════════════════════════════════
 *  types
 * ═════════════════════════════════════════════════════════════════ */

enum mdns_state {
	STATE_IDLE,
	STATE_PROBE_1,
	STATE_PROBE_2,
	STATE_PROBE_3,
	STATE_WAIT,
	STATE_ANNOUNCE_1,
	STATE_ANNOUNCE_2,
	STATE_STEADY,
	STATE_GOODBYE,
};

struct service {
	char instance[256];
	char fullname[512];
	uint16_t port;
	uint8_t *txt_data;
	int txt_len;
	bool active;
};

struct mdns {
	int fd;
	uint32_t printer_ip;
	char hostname[256];
	char hostname_fq[264];

	enum mdns_state state;
	uint64_t state_entered_ms;
	int probe_count;
	bool conflict;

	struct service services[MAX_SERVICES];
	int nservices;
	bool debug;
};

static uint64_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ═════════════════════════════════════════════════════════════════
 *  packet construction
 * ═════════════════════════════════════════════════════════════════ */

static uint8_t pkt_buf[DNS_MAX_PKT];

static bool send_probe(struct mdns *m) {
	struct dns_builder b;
	dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
	dns_hdr_write(&b, 0, 0, 0, 0, 0);
	if (dns_question_add(&b, m->hostname_fq, DNS_TYPE_ANY, true) < 0) return false;
	net_send_mcast(m->fd, pkt_buf, b.pos);
	if (m->debug) printf("[mdns] probe #%d: %s\n", m->probe_count, m->hostname_fq);
	return true;
}

static bool send_base_packet(struct mdns *m, uint32_t ttl, const struct sockaddr_in *to) {
	struct dns_builder b;
	dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
	dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);

	if (m->printer_ip && dns_a_add(&b, m->hostname_fq, ttl, m->printer_ip) < 0) return false;
	if (dns_ptr_add(&b, DNS_SD_NAME, ttl, SERVICE_TYPE) < 0) return false;

	if (to) {
		net_send_unicast(m->fd, pkt_buf, b.pos, to);
	} else {
		net_send_mcast(m->fd, pkt_buf, b.pos);
	}

	if (m->debug) {
		uint16_t an = ntohs(((struct dns_header *)pkt_buf)->ancount);
		printf("[mdns] %s %u records, TTL=%u\n", to ? "unicast" : "announce", an, ttl);
	}
	return true;
}

static bool send_service_packet(struct mdns *m, const struct service *s, uint32_t ttl, const struct sockaddr_in *to,
								bool include_host) {
	struct dns_builder b;
	dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
	dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);

	if (include_host && m->printer_ip && dns_a_add(&b, m->hostname_fq, ttl, m->printer_ip) < 0) return false;
	if (dns_ptr_add(&b, SERVICE_TYPE, ttl, s->fullname) < 0) return false;
	if (dns_ptr_add(&b, SUBTYPE_NAME, ttl, s->fullname) < 0) return false;
	if (dns_srv_add(&b, s->fullname, ttl, 0, 0, s->port, m->hostname_fq) < 0) return false;
	if (s->txt_len > 0 && dns_txt_add(&b, s->fullname, ttl, s->txt_data, (uint16_t)s->txt_len) < 0) return false;

	if (to) {
		net_send_unicast(m->fd, pkt_buf, b.pos, to);
	} else {
		net_send_mcast(m->fd, pkt_buf, b.pos);
	}
	return true;
}

static bool send_service_ptr_packet(struct mdns *m, const char *owner, const struct service *s, uint32_t ttl,
									const struct sockaddr_in *to) {
	struct dns_builder b;
	dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
	dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);

	if (dns_ptr_add(&b, owner, ttl, s->fullname) < 0) return false;

	if (to) {
		net_send_unicast(m->fd, pkt_buf, b.pos, to);
	} else {
		net_send_mcast(m->fd, pkt_buf, b.pos);
	}
	return true;
}

static bool send_instance_packet(struct mdns *m, const struct service *s, uint32_t ttl, const struct sockaddr_in *to) {
	struct dns_builder b;
	dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
	dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);

	if (dns_srv_add(&b, s->fullname, ttl, 0, 0, s->port, m->hostname_fq) < 0) return false;
	if (s->txt_len > 0 && dns_txt_add(&b, s->fullname, ttl, s->txt_data, (uint16_t)s->txt_len) < 0) return false;
	if (m->printer_ip && dns_a_add(&b, m->hostname_fq, ttl, m->printer_ip) < 0) return false;

	if (to) {
		net_send_unicast(m->fd, pkt_buf, b.pos, to);
	} else {
		net_send_mcast(m->fd, pkt_buf, b.pos);
	}
	return true;
}

static void send_announcement(struct mdns *m, uint32_t ttl) {
	if (!send_base_packet(m, ttl, NULL) && m->debug) {
		fprintf(stderr, "[mdns] failed to build base announcement\n");
	}
	for (int i = 0; i < m->nservices; i++) {
		struct service *s = &m->services[i];
		if (!s->active) continue;
		if (!send_service_packet(m, s, ttl, NULL, false) && m->debug) {
			fprintf(stderr, "[mdns] failed to build announcement for %s\n", s->fullname);
		}
	}
}

/* ═════════════════════════════════════════════════════════════════
 *  query handling
 * ═════════════════════════════════════════════════════════════════ */

static bool match_query(struct mdns *m, const char *qname, uint16_t qtype, bool *is_host, bool *is_svc_type,
						bool *is_subtype, bool *is_dns_sd, struct service **matched) {
	*is_host = *is_svc_type = *is_subtype = *is_dns_sd = false;
	*matched = NULL;

	if (strcasecmp(qname, m->hostname_fq) == 0) {
		*is_host = true;
		return true;
	}

	if (strcasecmp(qname, DNS_SD_NAME) == 0) {
		*is_dns_sd = true;
		return (qtype == DNS_TYPE_PTR || qtype == DNS_TYPE_ANY);
	}

	if (strcasecmp(qname, SERVICE_TYPE) == 0) {
		*is_svc_type = true;
		return (qtype == DNS_TYPE_PTR || qtype == DNS_TYPE_ANY);
	}

	if (strcasecmp(qname, SUBTYPE_NAME) == 0) {
		*is_subtype = true;
		return (qtype == DNS_TYPE_PTR || qtype == DNS_TYPE_ANY);
	}

	for (int i = 0; i < m->nservices; i++) {
		if (m->services[i].active && strcasecmp(qname, m->services[i].fullname) == 0) {
			*matched = &m->services[i];
			return (qtype == DNS_TYPE_SRV || qtype == DNS_TYPE_TXT || qtype == DNS_TYPE_ANY);
		}
	}

	return false;
}

static void send_response(struct mdns *m, const char *qname, uint16_t qtype, bool is_host, bool is_svc_type,
						  bool is_subtype, bool is_dns_sd, struct service *svc, const struct sockaddr_in *to) {
	bool sent = false;

	if (is_host && (qtype == DNS_TYPE_A || qtype == DNS_TYPE_ANY)) {
		struct dns_builder b;
		dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
		dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);
		if (dns_a_add(&b, m->hostname_fq, ANNOUNCE_TTL, m->printer_ip) < 0) return;
		if (to) {
			net_send_unicast(m->fd, pkt_buf, b.pos, to);
		} else {
			net_send_mcast(m->fd, pkt_buf, b.pos);
		}
		sent = true;
	}

	// For AAAA queries, respond with NSEC: "I have A, not AAAA"
	if (is_host && qtype == DNS_TYPE_AAAA) {
		struct dns_builder b;
		dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
		dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);
		uint16_t types[] = {DNS_TYPE_A};
		if (dns_nsec_add(&b, m->hostname_fq, ANNOUNCE_TTL, types, 1) < 0) return;
		if (to) net_send_unicast(m->fd, pkt_buf, b.pos, to);
		else net_send_mcast(m->fd, pkt_buf, b.pos);
		sent = true;
	}

	if (is_dns_sd) {
		if (send_base_packet(m, ANNOUNCE_TTL, to)) sent = true;
	}

	if (is_svc_type) {
		for (int i = 0; i < m->nservices; i++) {
			if (m->services[i].active && send_service_ptr_packet(m, SERVICE_TYPE, &m->services[i], ANNOUNCE_TTL, to)) {
				sent = true;
			}
		}
	}

	if (is_subtype) {
		for (int i = 0; i < m->nservices; i++) {
			if (m->services[i].active && send_service_ptr_packet(m, SUBTYPE_NAME, &m->services[i], ANNOUNCE_TTL, to)) {
				sent = true;
			}
		}
	}

	if (svc && send_instance_packet(m, svc, ANNOUNCE_TTL, to)) sent = true;

	if (sent && m->debug) {
		printf("[mdns] response: %s %s (%s)\n", qname, dns_type_str(qtype), to ? "unicast" : "multicast");
	}
}

struct query_ctx {
	struct mdns *m;
	const struct sockaddr_in *from;
	bool is_probe_period;
};

static bool on_question(const char *name, uint16_t type, uint16_t class_, void *user) {
	struct query_ctx *ctx = (struct query_ctx *)user;
	struct mdns *m = ctx->m;
	bool qu = (class_ & DNS_CLASS_QU) != 0;

	if (m->debug) printf("[mdns] query: %s %s (QU=%d)\n", name, dns_type_str(type), qu);

	bool is_host, is_svc_type, is_subtype, is_dns_sd;
	struct service *svc;

	if (!match_query(m, name, type, &is_host, &is_svc_type, &is_subtype, &is_dns_sd, &svc)) return true;

	if (m->state >= STATE_ANNOUNCE_1 && m->state != STATE_GOODBYE) {
		const struct sockaddr_in *to = qu ? ctx->from : NULL;
		send_response(m, name, type, is_host, is_svc_type, is_subtype, is_dns_sd, svc, to);
	}

	return true;
}

static bool on_rr(const char *name, uint16_t type, uint16_t class_, uint32_t ttl, const uint8_t *rdata, uint16_t rdlen,
				  void *user) {
	(void)type;
	(void)class_;
	(void)rdata;
	(void)rdlen;
	struct query_ctx *ctx = (struct query_ctx *)user;

	if (!ctx->is_probe_period) return true;

	if (strcasecmp(name, ctx->m->hostname_fq) == 0 && ttl > 0) {
		fprintf(stderr, "[mdns] CONFLICT: %s already claimed\n", name);
		ctx->m->conflict = true;
		return false;
	}
	return true;
}

/* ═════════════════════════════════════════════════════════════════
 *  public API
 * ═════════════════════════════════════════════════════════════════ */

struct mdns *mdns_create(const char *hostname, const char *ifname, uint32_t printer_ip, bool debug, bool loopback) {
	struct mdns *m = calloc(1, sizeof(*m));
	if (!m) return NULL;

	m->printer_ip = printer_ip;
	m->fd = -1;
	m->debug = debug;
	m->state = STATE_IDLE;
	m->state_entered_ms = now_ms();

	snprintf(m->hostname, sizeof(m->hostname), "%s", hostname && hostname[0] ? hostname : "cups-proxy");
	snprintf(m->hostname_fq, sizeof(m->hostname_fq), "%s.local", m->hostname);

	m->fd = net_init(ifname, loopback);
	if (m->fd < 0) {
		free(m);
		return NULL;
	}

	m->state = STATE_PROBE_1;
	m->probe_count = 1;
	m->state_entered_ms = now_ms();
	send_probe(m);

	if (m->debug) printf("[mdns] created, probing '%s'\n", m->hostname_fq);
	return m;
}

void mdns_destroy(struct mdns *m) {
	if (!m) return;
	if (m->fd >= 0) mdns_shutdown(m);
	for (int i = 0; i < m->nservices; i++)
		free(m->services[i].txt_data);
	free(m);
}

int mdns_service_set(struct mdns *m, const char *instance, int port, const uint8_t *txt_data, int txt_len) {
	if (!m || !instance) return -1;

	for (int i = 0; i < m->nservices; i++) {
		if (strcmp(m->services[i].instance, instance) == 0) {
			struct service *s = &m->services[i];
			free(s->txt_data);
			s->txt_data = NULL;
			s->txt_len = 0;
			if (txt_data && txt_len > 0) {
				s->txt_data = malloc((size_t)txt_len);
				if (s->txt_data) {
					memcpy(s->txt_data, txt_data, (size_t)txt_len);
					s->txt_len = txt_len;
				}
			}
			s->port = (uint16_t)port;
			s->active = true;
			if (m->state >= STATE_ANNOUNCE_1 && m->state != STATE_GOODBYE) send_announcement(m, ANNOUNCE_TTL);
			return 0;
		}
	}

	if (m->nservices >= MAX_SERVICES) return -1;
	struct service *s = &m->services[m->nservices++];
	memset(s, 0, sizeof(*s));
	snprintf(s->instance, sizeof(s->instance), "%s", instance);
	snprintf(s->fullname, sizeof(s->fullname), "%s.%s", instance, SERVICE_TYPE);
	s->port = (uint16_t)port;
	s->active = true;
	if (txt_data && txt_len > 0) {
		s->txt_data = malloc((size_t)txt_len);
		if (s->txt_data) {
			memcpy(s->txt_data, txt_data, (size_t)txt_len);
			s->txt_len = txt_len;
		}
	}
	if (m->state >= STATE_ANNOUNCE_1 && m->state != STATE_GOODBYE) send_announcement(m, ANNOUNCE_TTL);
	if (m->debug) printf("[mdns] service set: %s port=%d\n", s->fullname, port);
	return 0;
}

void mdns_service_remove(struct mdns *m, const char *instance) {
	if (!m || !instance) return;
	for (int i = 0; i < m->nservices; i++) {
		if (strcmp(m->services[i].instance, instance) == 0) {
			struct service *s = &m->services[i];
			if (m->state >= STATE_ANNOUNCE_1 && m->state != STATE_GOODBYE) {
				struct dns_builder b;
				dns_builder_init(&b, pkt_buf, sizeof(pkt_buf));
				dns_hdr_write(&b, DNS_FLAG_QR | DNS_FLAG_AA, 0, 0, 0, 0);
				dns_ptr_add(&b, SERVICE_TYPE, 0, s->fullname);
				dns_ptr_add(&b, SUBTYPE_NAME, 0, s->fullname);
				dns_srv_add(&b, s->fullname, 0, 0, 0, s->port, m->hostname_fq);
				if (s->txt_len > 0) dns_txt_add(&b, s->fullname, 0, s->txt_data, (uint16_t)s->txt_len);
				net_send_mcast(m->fd, pkt_buf, b.pos);
			}
			free(s->txt_data);
			if (i < m->nservices - 1)
				memmove(&m->services[i], &m->services[i + 1], (size_t)(m->nservices - i - 1) * sizeof(*s));
			m->nservices--;
			if (m->debug) printf("[mdns] removed: %s\n", instance);
			return;
		}
	}
}

void mdns_service_remove_all(struct mdns *m) {
	if (!m) return;
	for (int i = m->nservices - 1; i >= 0; i--)
		mdns_service_remove(m, m->services[i].instance);
}

int mdns_fd(struct mdns *m) {
	return m ? m->fd : -1;
}

void mdns_on_readable(struct mdns *m) {
	if (!m) return;
	uint8_t buf[DNS_MAX_PKT];
	struct sockaddr_in from;
	int n = net_recv(m->fd, buf, sizeof(buf), &from);
	if (n <= 0) return;

	struct query_ctx ctx = {
		.m = m,
		.from = &from,
		.is_probe_period = (m->state >= STATE_PROBE_1 && m->state <= STATE_WAIT),
	};
	struct dns_parse_callbacks cb = {
		.on_question = on_question,
		.on_answer = on_rr,
		.on_authority = on_rr,
		.on_additional = NULL,
	};

	if (m->debug) {
		char src[64];
		inet_ntop(AF_INET, &from.sin_addr, src, sizeof(src));
		uint16_t f = ntohs(((struct dns_header *)buf)->flags);
		uint16_t q = ntohs(((struct dns_header *)buf)->qdcount);
		printf("[mdns] recv %s %d bytes from %s:%d (qd=%u)\n", (f & DNS_FLAG_QR) ? "response" : "query", n, src,
			   ntohs(from.sin_port), q);
	}

	dns_packet_parse(buf, (size_t)n, &cb, &ctx);
}

void mdns_on_timer(struct mdns *m) {
	if (!m || m->state == STATE_IDLE || m->state == STATE_GOODBYE) return;
	uint64_t elapsed = now_ms() - m->state_entered_ms;

	switch (m->state) {
		case STATE_PROBE_1:
		case STATE_PROBE_2:
			if (elapsed >= PROBE_INTERVAL_MS) {
				m->probe_count++;
				m->state = (m->state == STATE_PROBE_1) ? STATE_PROBE_2 : STATE_PROBE_3;
				m->state_entered_ms = now_ms();
				send_probe(m);
			}
			break;
		case STATE_PROBE_3:
			if (elapsed >= PROBE_INTERVAL_MS) {
				m->state = STATE_WAIT;
				m->state_entered_ms = now_ms();
				if (m->debug) printf("[mdns] probe done, waiting...\n");
			}
			break;
		case STATE_WAIT:
			if (elapsed >= WAIT_INTERVAL_MS) {
				if (m->conflict) {
					fprintf(stderr, "[mdns] conflicted\n");
					m->state = STATE_IDLE;
				} else {
					m->state = STATE_ANNOUNCE_1;
					m->state_entered_ms = now_ms();
					send_announcement(m, ANNOUNCE_TTL);
					if (m->debug) printf("[mdns] announce #1\n");
				}
			}
			break;
		case STATE_ANNOUNCE_1:
			if (elapsed >= ANNOUNCE_GAP_MS) {
				m->state = STATE_ANNOUNCE_2;
				m->state_entered_ms = now_ms();
				send_announcement(m, ANNOUNCE_TTL);
				if (m->debug) printf("[mdns] announce #2\n");
			}
			break;
		case STATE_ANNOUNCE_2:
			m->state = STATE_STEADY;
			m->state_entered_ms = now_ms();
			if (m->debug) printf("[mdns] STEADY\n");
			break;
		case STATE_STEADY: {
			int64_t re = (int64_t)ANNOUNCE_TTL * 1000 * REANNOUNCE_FACTOR / 100;
			if ((int64_t)elapsed >= re) {
				send_announcement(m, ANNOUNCE_TTL);
				m->state_entered_ms = now_ms();
				if (m->debug) printf("[mdns] re-announce\n");
			}
			break;
		}
		default:
			break;
	}
}

int mdns_next_timeout_ms(struct mdns *m) {
	if (!m) return -1;
	switch (m->state) {
		case STATE_IDLE:
		case STATE_GOODBYE:
			return -1;
		case STATE_PROBE_1:
		case STATE_PROBE_2:
		case STATE_PROBE_3: {
			int r = PROBE_INTERVAL_MS - (int)(now_ms() - m->state_entered_ms);
			return r > 0 ? r : 1;
		}
		case STATE_WAIT: {
			int r = WAIT_INTERVAL_MS - (int)(now_ms() - m->state_entered_ms);
			return r > 0 ? r : 1;
		}
		case STATE_ANNOUNCE_1: {
			int r = ANNOUNCE_GAP_MS - (int)(now_ms() - m->state_entered_ms);
			return r > 0 ? r : 1;
		}
		case STATE_ANNOUNCE_2:
			return 1;
		case STATE_STEADY: {
			int64_t re = (int64_t)ANNOUNCE_TTL * 1000 * REANNOUNCE_FACTOR / 100;
			int64_t r = re - (int64_t)(now_ms() - m->state_entered_ms);
			if (r < 1000) r = 1000;
			if (r > 3600000) r = 3600000;
			return (int)r;
		}
		default:
			return 1000;
	}
}

void mdns_shutdown(struct mdns *m) {
	if (!m || m->fd < 0) return;
	if (m->state >= STATE_ANNOUNCE_1 && m->state != STATE_GOODBYE) {
		m->state = STATE_GOODBYE;
		send_announcement(m, 0);
		usleep(100000);
	}
	net_close(m->fd);
	m->fd = -1;
	m->state = STATE_IDLE;
	if (m->debug) printf("[mdns] shutdown\n");
}
