/*
 * nbee_link.h 
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef NBEE_LINK_H_
#define NBEE_LINK_H_

#include <stdio.h>
#include <stdint.h>
#include "../lib/list_t.h"
#include "../lib/hmap.h"
#include "../lib/ofpbuf.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256


typedef struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
}pcap_pkthdr_t;

typedef struct field_values {
       list_t list_node;
       uint8_t* value;
}field_values_t;

typedef struct packet_fields{
       struct hmap_node hmap_node;
           uint32_t header;                  /* NXM_* value. */
           list_t fields;              /* List of field values (In one packet, there may be more than one value per field) */
}packet_fields_t;

#ifdef __cplusplus
extern "C"
#endif
int nbee_link_initialize();

#ifdef __cplusplus
extern "C"
#endif
int nbee_link_convertpkt(struct ofpbuf * pkt_in, struct hmap * pkt_out);

#endif /* NBEE_LINK_H_ */
