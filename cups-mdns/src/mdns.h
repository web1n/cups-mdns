/*
 * mdns.h — mDNS responder state machine and service management
 */

#ifndef MDNS_H
#define MDNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Opaque handle
struct mdns;

// ── lifecycle ───────────────────────────────────────────────────

/* Create a responder.  hostname is the label (without .local suffix).
 * ifname is the network interface (e.g. "eth0"), may be NULL for default.
 * printer_ip is the IPv4 address for the mDNS A record address (host byte order).
 * debug enables verbose logging to stdout.
 * loopback enables multicast loopback (disabled by default per RFC 6762). */
struct mdns *mdns_create(const char *hostname, const char *ifname, uint32_t printer_ip, bool debug, bool loopback);
void mdns_destroy(struct mdns *m);

// ── service management ──────────────────────────────────────────

/* Add or update a service.  instance is the human-readable name
 * (e.g. "OfficeLaser").  port is the TCP port.  txt_data/txt_len
 * is the pre-built Printer TXT rdata.
 * Returns 0 on success, -1 on error. */
int mdns_service_set(struct mdns *m, const char *instance, int port, const uint8_t *txt_data, int txt_len);

// Remove a service. Sends goodbye (TTL=0) if it was announced.
void mdns_service_remove(struct mdns *m, const char *instance);

// Remove all services.
void mdns_service_remove_all(struct mdns *m);

// ── event loop integration ──────────────────────────────────────

int mdns_fd(struct mdns *m);
void mdns_on_readable(struct mdns *m);
void mdns_on_timer(struct mdns *m);
int mdns_next_timeout_ms(struct mdns *m);

// ── shutdown ────────────────────────────────────────────────────

void mdns_shutdown(struct mdns *m);

#endif // MDNS_H
