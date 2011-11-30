/*
 * Copyright (c) 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NX_MATCH_H
#define NX_MATCH_H 1

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "ofpbuf.h"
#include "hmap.h"
#include "packets.h"
#include "openflow/match-ext.h"
#include "oflib-exp/ofl-exp-match.h"


struct nxm_field {
    struct hmap_node hmap_node;
    uint32_t header;                  /* TLV_* value. */
    uint32_t length;                  /* Value size. */
    uint8_t *value;
    uint8_t * mask;
};


int 
ext_pull_match(struct ofl_ext_match * match_src, struct hmap *match_dst);

char *ext_match_to_string(const uint8_t *, unsigned int match_len);

int ext_match_from_string(const char *, struct ofpbuf *);

uint32_t ext_entry_ok(const void *, unsigned int );

int
ext_field_bytes(uint32_t header);

int
nxm_field_bits(uint32_t header);

void
ext_put_header(struct flex_array *f, uint32_t header);

void
ext_put_8(struct flex_array *f, uint32_t header, uint8_t value);

void
ext_put_8w(struct flex_array *f, uint32_t header, uint8_t value, uint16_t mask);

void
ext_put_16(struct flex_array *f, uint32_t header, uint16_t value);

void
ext_put_16w(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask);

void
ext_put_16m(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask);

void
ext_put_32(struct flex_array *f, uint32_t header, uint32_t value);

void
ext_put_32w(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask);

void
ext_put_32m(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask);

void
ext_put_64(struct flex_array *f, uint32_t header, uint64_t value);

void
ext_put_64w(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask);

void
ext_put_64m(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask);

void
ext_put_eth(struct flex_array *f, uint32_t header,
            const uint8_t value[ETH_ADDR_LEN]);
            
void ext_put_ipv6(struct flex_array *f, uint32_t header,
                    const struct in6_addr *value, const struct in6_addr *mask);


#endif /* nx-match.h */
