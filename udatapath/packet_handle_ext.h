#ifndef PACKET_HANDLE_EXT_H
#define PACKET_HANDLE_EXT_H 1

#include <stdbool.h>
#include <stdio.h>
#include "packet.h"
#include "packets.h"
#include "oflib/ofl-structs.h"
#include "nbee_link/nbee_link.h"

/****************************************************************************
 * A handler processing a datapath packet for standard matches.
 ****************************************************************************/

/* The data associated with the handler */
struct packet_handle_ext {
    struct packet              *pkt;
    struct hmap                *fields; /* All fields extracted from the packet
					    	*/
    bool                        valid; /* Set to true if the handler data is valid.
                                            if false, it is revalidated before
                                            executing any methods. */
};

/* Creates a handler */
struct packet_handle_ext *
packet_handle_ext_create(struct packet *pkt);

/* Destroys a handler */
void
packet_handle_ext_destroy(struct packet_handle_ext *handle);

/* Returns true if the TTL fields of the supported protocols are valid. */
bool
packet_handle_ext_is_ttl_valid(struct packet_handle_ext *handle);

/* Returns true if the packet is a fragment (IPv4). */
bool
packet_handle_ext_is_fragment(struct packet_handle_ext *handle);

/* Returns true if the packet matches the given standard match structure. */
bool
packet_handle_ext_match(struct packet_handle_ext *handle, struct ofl_match_standard *match);

/* Converts the packet to a string representation */
char *
packet_handle_ext_to_string(struct packet_handle_ext *handle);

void
packet_handle_ext_print(FILE *stream, struct packet_handle_ext *handle);

/* Clones the handler, and associates it with the new packet. */
struct packet_handle_ext *
packet_handle_ext_clone(struct packet *pkt, struct packet_handle_ext *handle);

/* Revalidates the handler data */
void
packet_handle_ext_validate(struct packet_handle_ext *handle);


#endif /* PACKET_HANDLE_EXT_H */
