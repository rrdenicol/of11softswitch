/*
 * nbee_link.h 
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef TEST_HPP_
#define TEST_HPP_

#include <stdio.h>
#include <stdint.h>
#include "list_t.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256

typedef struct pktfields {
	char *name;
	int len;
	short *value;
} pktfields_t;

typedef struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
}pcap_pkthdr_t;

struct ethernetpkt {
	short ethdst[ETHADDLEN];
	short ethsrc[ETHADDLEN];
	short ethtype[ETHTYPELEN];
};

struct ipv6pkt {
	short ipv6dst[IPV6ADDLEN];
	short ipv6src[IPV6ADDLEN];

};

typedef struct packet_out{
	list_t node;
	uint32_t type;
	uint16_t length;
	uint8_t* value;
}packet_out_t;

#ifdef __cplusplus
extern "C"
#endif
int initialize_nb_engine();

#ifdef __cplusplus
extern "C"
#endif
int convertpkt_test(const unsigned char* pkt_in, list_t * pkt_out);

#endif /* TEST_HPP_ */
