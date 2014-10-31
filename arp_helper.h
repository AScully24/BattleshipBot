#ifndef __ARP_HELPER_H
#define __ARP_HELPER_H

#include "pcap.h"

int get_remote_mac(pcap_t *cap_dev, const u_char *if_addr, u_long sip, u_long dip, u_char *remote_mac);

/* Create an ARP request according to the given parameters */
void generate_arp_request(u_char *packet, const u_char *if_addr, u_long sip, u_long dip);

/* Create an ARP reply according to the given parameters */
void generate_arp_reply(u_char *packet, const u_char *if_addr, const u_char *dst_haddr, u_long sip, u_long dip);

int process_arp_reply(struct pcap_pkthdr *header, const u_char *pkt_data, u_long sip, u_long dip, u_char *mac_result);

#endif