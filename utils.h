
#ifndef __UTILS_H
#define __UTILS_H

char *mactos(const u_char *addr);
char *iptos(u_long in);

/* Fill a given buffer with the MAC address corresponding to a specific device */
int get_if_mac(const char *dev_name, u_char *mac_addr);

#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define _CRT_SECURE_NO_WARNINGS

#include "pcap.h"
#include "ether.h"
//#include "utils.h"

#include <stdio.h>

/* We need this for GetAdaptersInfo and the relevant data structures */
#include <Iphlpapi.h>

#define MACTOSBUFFERS	12
#define IPTOSBUFFERS	12

char *mactos(const u_char *addr) {

	static char output[MACTOSBUFFERS][(ETH_ALEN-1)*3+2+1];
	static short which;
	int idx;
	
	which = (which + 1) % IPTOSBUFFERS;
	sprintf(output[which], "%02X", addr[0]);
	for (idx = 1; idx < ETH_ALEN; idx++)
		sprintf(output[which] + 2 + (idx - 1) * 3, ":%02X", addr[idx]);
	return output[which];
}

/* From tcptraceroute, convert a numeric IP address to a string */
char *iptos(u_long in)
{

	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1) % IPTOSBUFFERS;
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/* Fill a given buffer with the MAC address corresponding to a specific device */
int get_if_mac(const char *dev_name, u_char *mac_addr) {

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;

	pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO) );
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen); 
		if (pAdapterInfo == NULL)
			return -1;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			/* We're looking for an Ethernet adapter */
			if (pAdapter->AddressLength == ETH_ALEN) {
				/* Not accurate, but good enough */
				if (strstr(dev_name, pAdapter->AdapterName) != NULL) {
					memcpy(mac_addr, pAdapter->Address, ETH_ALEN);
					break;
				}
			}
			pAdapter = pAdapter->Next;
		}
	}
	else {
		if (pAdapterInfo)
			free(pAdapterInfo);
		return -2;
	}
	if (pAdapterInfo)
		free(pAdapterInfo);
	return 0;
}