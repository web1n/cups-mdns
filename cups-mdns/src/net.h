/*
 * net.h — IPv4 multicast socket for mDNS
 */

#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Create and bind an mDNS multicast socket on the given interface.
 * Returns fd on success, -1 on error. */
int net_init(const char *ifname, bool loopback);

// Send a raw DNS packet to the mDNS multicast group.
int net_send_mcast(int fd, const uint8_t *pkt, size_t len);

// Send a raw DNS packet to a specific unicast address.
int net_send_unicast(int fd, const uint8_t *pkt, size_t len, const struct sockaddr_in *to);

/* Receive a raw DNS packet.  Returns bytes read (>0), 0 on signal,
 * or -1 on error.  Fills *from_addr if non-NULL. */
int net_recv(int fd, uint8_t *buf, size_t cap, struct sockaddr_in *from);

// Close the socket.
void net_close(int fd);

// Return the local IPv4 address of the bound interface (host order).
uint32_t net_local_ip(int fd);

#endif // NET_H
