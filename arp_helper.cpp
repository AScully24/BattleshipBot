
#include "stdafx.h"
#include "pcap.h"
#include "ether.h"
#include "arp.h"
#include "arp_helper.h"

#define CAP_MAX_TIMEOUTS 65
//#define CAP_MAX_TIMEOUTS 100
//#define CAP_MAX_PACKETS 100

#define CAP_MAX_PACKETS	65

int get_remote_mac(pcap_t *cap_dev, const u_char *if_addr, u_long sip, u_long dip, u_char *remote_mac) {
	
	u_char arp_packet[sizeof(struct ethhdr) + sizeof(arphdr_ether)];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res = 0;

	/* In case we fail */
	memset(remote_mac, 0, ETH_ALEN);

	/* Build the ARP request packet */
	generate_arp_request(arp_packet, if_addr, sip, dip);
	/* Send the ARP request */
	/* There's a race condition here because the reply might arrive before we capture it */
	if (pcap_sendpacket(cap_dev, arp_packet, sizeof(arp_packet)) != 0)
		return -1;
	int timeouts = 0;
	int packets = 0;
	/* Start the capture */
 	while ((res = pcap_next_ex(cap_dev, &header, &pkt_data)) >= 0)
	{

		//static int timeouts = 0;
		//static int packets = 0;

		/* Timeout elapsed? */
		if (res == 0) {
			if (++timeouts > CAP_MAX_TIMEOUTS)
				break;
		}
		else {
			/* Look for the ARP reply (source and destination are reversed) */
			if (process_arp_reply(header, pkt_data, dip, sip, remote_mac) == 0)
			{
				printf("t:%d, p:%d\t",timeouts,packets);
				return 0;
			}
			/* Seen too many packets without finding ours? */
			if (++packets >= CAP_MAX_PACKETS)
						break;
		}
	}
	/* Didn't receive the appropriate ARP reply */
	return -2;
}

/* Create an ARP request according to the given parameters */
void generate_arp_request(u_char *packet, const u_char *if_addr, u_long sip, u_long dip) {

	struct ethhdr *ethp;
	struct arphdr_ether *arpp;

	/* Fill Ethernet data */
	ethp = (struct ethhdr *)packet;
	ethp->h_proto = htons(ETHERTYPE_ARP);
	memcpy(ethp->h_source, if_addr, ETH_ALEN);
	/* Send to the broadcast address */
	memset(ethp->h_dest, 0xFF, ETH_ALEN);

	/* Fill ARP data */
	arpp = (struct arphdr_ether *)(packet + sizeof(struct ethhdr));
	arpp->ar_hrd = htons(ARPHRD_ETHER);
	arpp->ar_pro = htons(ETHERTYPE_IP);
	arpp->ar_hln = ETH_ALEN;
	arpp->ar_pln = sizeof(u_long);
	arpp->ar_op = htons(ARPOP_REQUEST);
	memcpy(arpp->ar_sha, if_addr, ETH_ALEN);
	memcpy(arpp->ar_sip, &sip, sizeof(u_long));
	/* We don't know who the target is */
	memset(arpp->ar_tha, 0, ETH_ALEN);
	memcpy(arpp->ar_tip, &dip, sizeof(u_long));
}

/* Create an ARP reply according to the given parameters */
void generate_arp_reply(u_char *packet, const u_char *if_addr, const u_char *dst_haddr, u_long sip, u_long dip) {

	struct ethhdr *ethp;
	struct arphdr_ether *arpp;

	/* Fill Ethernet data */
	ethp = (struct ethhdr *)packet;
	ethp->h_proto = htons(ETHERTYPE_ARP);
	memcpy(ethp->h_source, if_addr, ETH_ALEN);
	/* Send to the destination address */
	memcpy(ethp->h_dest, dst_haddr, ETH_ALEN);

	/* Fill ARP data */
	arpp = (struct arphdr_ether *)(packet + sizeof(struct ethhdr));
	arpp->ar_hrd = htons(ARPHRD_ETHER);
	arpp->ar_pro = htons(ETHERTYPE_IP);
	arpp->ar_hln = ETH_ALEN;
	arpp->ar_pln = sizeof(u_long);
	arpp->ar_op = htons(ARPOP_REPLY);
	memcpy(arpp->ar_sha, if_addr, ETH_ALEN);
	memcpy(arpp->ar_sip, &sip, sizeof(u_long));
	memcpy(arpp->ar_tha, dst_haddr, ETH_ALEN);
	memcpy(arpp->ar_tip, &dip, sizeof(u_long));
}

int process_arp_reply(struct pcap_pkthdr *header, const u_char *pkt_data, u_long sip, u_long dip, u_char *remote_mac) {

	const struct ethhdr *ethp;
	const struct arphdr_ether *arpp;

	/* Sanity checks */
	if (header->caplen < sizeof(struct ethhdr) + sizeof(arphdr_ether))
		/* Packet too small */
		return -1;

	ethp = (struct ethhdr *)pkt_data;
	if (ethp->h_proto != htons(ETHERTYPE_ARP))
		/* Not an ARP packet */
		return -2;

	arpp = (struct arphdr_ether *)(pkt_data + sizeof(struct ethhdr));
	if (arpp->ar_hrd != htons(ARPHRD_ETHER))
		/* ARP not for Ethernet */
		return -3;
	if (arpp->ar_pro != htons(ETHERTYPE_IP))
		/* ARP not for IP */
		return -4;

	if (ntohs(arpp->ar_op) != ARPOP_REPLY)
		/* Not an ARP reply */
		return -5;

	if (*((u_long *)&(arpp->ar_sip)) != sip)
		/* Not the source we were looking for */
		return -6;

	if (*((u_long *)&(arpp->ar_tip)) != dip)
		/* Not the destination we were looking for */
		return -7;

	/* Everything looks ok - copy the ethernet address of the sender */
	memcpy(remote_mac, arpp->ar_sha, ETH_ALEN);
	return 0;
}

