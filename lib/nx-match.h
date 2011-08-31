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
#include "openflow/match-ext.h"
#include "oflib-exp/ofl-exp-match.h"


//typedef unsigned int __attribute__((bitwise)) flow_wildcards_t;

/* Nicira Extended Match (NXM) flexible flow match helper functions.
 *
 * See include/openflow/ext-match.h for NXM specification.
 */

int ext_pull_match(struct ofpbuf *, unsigned int match_len, uint16_t priority);

int
nx_ntoh(struct ext_match *match_src, struct ofl_ext_match * match_dst, unsigned int match_len);

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
ext_put_32(struct flex_array *f, uint32_t header, uint32_t value);

void
ext_put_16(struct flex_array *f, uint32_t header, uint16_t value);

/* Upper bound on the length of an nx_match.  The longest nx_match (assuming
 * we implement 4 registers) would be:
 *
 *                   header  value  mask  total
 *                   ------  -----  ----  -----
 *  NXM_OF_IN_PORT      4       2    --      6
 *  NXM_OF_ETH_DST_W    4       6     6     16
 *  NXM_OF_ETH_SRC      4       6    --     10
 *  NXM_OF_ETH_TYPE     4       2    --      6
 *  NXM_OF_VLAN_TCI     4       2     2      8
 *  NXM_OF_IP_TOS       4       1    --      5
 *  NXM_OF_IP_PROTO     4       2    --      6
 *  NXM_OF_IPV6_SRC_W   4      16    16     36
 *  NXM_OF_IPV6_DST_W   4      16    16     36
 *  NXM_OF_ICMP_TYPE    4       1    --      5
 *  NXM_OF_ICMP_CODE    4       1    --      5
 *  NXM_NX_ND_TARGET    4      16    --     20 
 *  NXM_NX_ND_SLL       4       6    --     10 
 *  NXM_NX_REG_W(0)     4       4     4     12
 *  NXM_NX_REG_W(1)     4       4     4     12
 *  NXM_NX_REG_W(2)     4       4     4     12
 *  NXM_NX_REG_W(3)     4       4     4     12
 *  NXM_NX_TUN_ID_W     4       8     8     20
 *  -------------------------------------------
 *  total                                  237
 *
 * So this value is conservative.
 */
#define NXM_MAX_LEN 256

/* This is my guess at the length of a "typical" nx_match, for use in
 * predicting space requirements. */
#define NXM_TYPICAL_LEN 64

#endif /* nx-match.h */
