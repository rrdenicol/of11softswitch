/*
 * Copyright (c) 2011 CPqD.
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

#include <config.h>

#include "nx-match.h"

#include <netinet/icmp6.h>

#include "bj_hash.h"
#include "byte-order.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "unaligned.h"
#include "vlog.h"
#include "ofpbuf.h"
#include "flex-array.h"
#include "openflow/match-ext.h"
#include "oflib-exp/ofl-exp-match.h"

#define LOG_MODULE VLM_nx_match


/* For each TLV_* field, define NFI_TLV_* as consecutive integers starting from
 * zero. */
enum nxm_field_index {
#define DEFINE_FIELD(HEADER, WILDCARD, DL_TYPES, NW_PROTO) \
        NFI_TLV_##HEADER,
#include "nx-match.def"
    N_TLV_FIELDS
};




/* Possible masks for TLV_EXT_DL_DST_W. */
static const uint8_t eth_all_0s[ETH_ADDR_LEN]
    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t eth_all_1s[ETH_ADDR_LEN]
    = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const uint8_t eth_mcast_1[ETH_ADDR_LEN]
    = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t eth_mcast_0[ETH_ADDR_LEN]
    = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
mod_match(struct hmap * flow ){


    struct nxm_field *f;
    uint16_t *dl_type = malloc(sizeof(uint16_t));
    uint16_t *dl_type_m ;
    uint8_t *nw_proto = malloc(sizeof(uint8_t));
    uint8_t *nw_proto_m ;
    
    *nw_proto = *dl_type = 0x0000;
       
    HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_DL_TYPE, 0),
          flow) {
            dl_type = (uint16_t*) f->value;
            dl_type_m = (uint16_t*) f->mask;
        
            
            if( (*dl_type & ~(*dl_type_m)) == 0){
              
                *dl_type = 0x0000;
                 f->value = (uint8_t*) dl_type;
            }
    }    
    /* IPv4 / ARP */
    if (*dl_type != ETH_TYPE_IP && *dl_type != ETH_TYPE_ARP) {
                  
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_NW_TOS, 0),
            flow) {
                    
            /*uint16_t *nw_tos = malloc (sizeof(uint16_t));
            uint16_t *nw_tos_m = malloc (sizeof(uint16_t)); 
            *nw_tos = 0x00;
            *nw_tos_m = 0xff;
            f->value = (uint8_t*) nw_tos;
            f->mask = (uint8_t*) nw_tos_m;*/
            hmap_remove(flow,&f->hmap_node);
        }
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_NW_PROTO, 0),
                    flow) {
            
            /*nw_proto = malloc (sizeof(uint8_t));
            nw_proto_m = malloc (sizeof(uint8_t));        
            *nw_proto = 0x0000;
            *nw_proto_m = 0xff;
            f->value = (uint8_t*) nw_proto;
            f->mask = (uint8_t*) nw_proto_m;*/
            hmap_remove(flow,&f->hmap_node);
        }
                
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_IP_SRC, 0),
                flow) {
           
            /*uint32_t *ip_src = malloc (sizeof(int));
            uint32_t *ip_src_m = malloc (sizeof(int)); 
            *ip_src = 0x00000000;
            *ip_src_m = 0xffffffff;
            f->value = (uint8_t*) ip_src;
            f->mask = (uint8_t*) ip_src_m;*/
            hmap_remove(flow,&f->hmap_node);
        }
        
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_IP_DST, 0),
                flow) {
                    
            /*uint32_t *ip_dst = malloc (sizeof(int)); 
            uint32_t *ip_dst_m = malloc (sizeof(int));;
            *ip_dst = 0x00000000;
            *ip_dst_m = 0xffffffff;
            f->value = (uint8_t*) ip_dst;
            f->mask = (uint8_t*) ip_dst_m;*/
            hmap_remove(flow,&f->hmap_node);
        }                          
                 
    }
    /* Transport */ 
    HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_NW_PROTO, 0),
               flow) {
                      
        nw_proto =  f->value;
    }                
        
    if (*nw_proto != IP_TYPE_ICMP && *nw_proto != IP_TYPE_TCP &&
        *nw_proto != IP_TYPE_UDP  && *nw_proto != IP_TYPE_SCTP) {

        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_TP_SRC, 0),
                flow) {
            /*uint16_t *tp_src = malloc (sizeof(uint16_t)); 
            uint16_t *tp_src_m = malloc (sizeof(uint16_t));
            *tp_src = 0x0000;
            *tp_src_m = 0xffff;
            f->value = (uint8_t*) tp_src;
            f->mask = (uint8_t*) tp_src_m;*/
            hmap_remove(flow,&f->hmap_node);
        }
                        
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_TP_DST, 0),
                flow) {
            /*uint16_t *tp_dst = malloc (sizeof(uint16_t)); 
            uint16_t *tp_dst_m = malloc (sizeof(uint16_t));
            *tp_dst = 0x0000;
            *tp_dst_m = 0xffff;
            f->value = (uint8_t*) tp_dst;
            f->mask = (uint8_t*) tp_dst_m;*/
            hmap_remove(flow,&f->hmap_node);
                        
         }        
                    
    }
            
     /* MPLS */
    if (*dl_type != ETH_TYPE_MPLS && *dl_type != ETH_TYPE_MPLS_MCAST) {
          
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_MPLS_LABEL, 0),
                flow) {
           /* uint32_t *mpls_label = malloc (sizeof(uint16_t)); 
            uint32_t *mpls_label_m = malloc (sizeof(uint16_t));
            *mpls_label = 0x00000000;
            *mpls_label_m = 0xffffffff;
            f->value = (uint8_t*) mpls_label;
            f->mask = (uint8_t*) *mpls_label_m;*/
            hmap_remove(flow,&f->hmap_node);
        }
                        
        HMAP_FOR_EACH_WITH_HASH (f, struct nxm_field, hmap_node, hash_int(TLV_EXT_MPLS_TC, 0),
                flow) {
            /*uint16_t *mpls_tc = malloc (sizeof(uint16_t)); 
            uint16_t *mpls_tc_m = malloc (sizeof(uint16_t));
            *mpls_tc = 0x0000;
            *mpls_tc_m = 0xffff;
            f->value = (uint8_t*) mpls_tc;
            f->mask = (uint8_t*) mpls_tc_m;*/
            hmap_remove(flow,&f->hmap_node);
                        
         }              
                         
    }
                         
}
   

int 
ext_pull_match(struct ofl_ext_match *match_src, struct hmap * match_dst)
{

    uint32_t header, match_len;
    
    uint8_t *p =  match_src->match_fields.entries;
    if (!p) {
        return 1;
    }
    match_len = match_src->match_fields.size;
    while ((header = ext_entry_ok(p, match_len)) != 0) {
        struct nxm_field *f = (struct nxm_field *) malloc(sizeof(struct nxm_field)); 
        unsigned length = NXM_LENGTH(header);
        f->header = header;
        f->value = p + 4;
        if (NXM_HASMASK(header)){
            f->mask = p + 4 + length / 2;
            f->header = NXM_HEADER( NXM_VENDOR(header), NXM_FIELD(header), NXM_LENGTH(header)/2);
            f->length = length/2;
        }
        else {
            f->mask = malloc(length);
            memset(f->mask,0x0,length);
            f->length = length;
            
            }      
        hmap_insert(match_dst, &f->hmap_node,
                        hash_int(f->header, 0));
                        
    
        p += 4 + length;
        match_len -= 4 + length;
        
    }
    mod_match(match_dst);
    
    return match_len ? 1 : 0;
}

/* nx_pull_match() and helpers. */


uint32_t
ext_entry_ok(const void *p, unsigned int match_len)
{
    unsigned int payload_len;
    uint32_t header;
    
    if (match_len < 4) {
        if (match_len) {
            VLOG_DBG(LOG_MODULE,"ext_match ends with partial ext_header");
        }
        return 0;
    }

    memcpy(&header, p, 4);
    payload_len = NXM_LENGTH(header);
    if (!payload_len) {
        VLOG_DBG(LOG_MODULE, "ext_entry %08"PRIx32" has invalid payload "
                    "length 0", header);
        return 0;
    }
    if (match_len < payload_len + 4) {
        VLOG_DBG(LOG_MODULE, "%"PRIu32"-byte ext_entry but only "
                    "%u bytes left in nx_match", payload_len + 4, match_len);
        return 0;
    }
    return header;
}

/* ext_put_match() and helpers.
 *
 * 'put' functions whose names end in 'w' add a wildcarded field.
 * 'put' functions whose names end in 'm' add a field that might be wildcarded.
 * Other 'put' functions add exact-match fields.
 */

void
ext_put_header(struct flex_array *f, uint32_t header)
{ 
   flex_array_put(f, &header, sizeof header);

}

void
ext_put_8(struct flex_array *f, uint32_t header, uint8_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    f->total++;
}

void
ext_put_8w(struct flex_array *f, uint32_t header, uint8_t value, uint16_t mask){

    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
    f->total++;

}

void
ext_put_16(struct flex_array *f, uint32_t header, uint16_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    f->total++;
}

void
ext_put_16w(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask)
{

    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
    f->total++;
}

void
ext_put_16m(struct flex_array *f, uint32_t header, uint16_t value, uint16_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONS(UINT16_MAX):
        ext_put_16(f, header, value);
        break;

    default:
        ext_put_16w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_32(struct flex_array *f, uint32_t header, uint32_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value); 
    f->total++;
    
}

void
ext_put_32w(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask)
{
    
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
}

void
ext_put_32m(struct flex_array *f, uint32_t header, uint32_t value, uint32_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONL(UINT32_MAX):
        ext_put_32(f, header, value);
        break;

    default:
        ext_put_32w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_64(struct flex_array *f, uint32_t header, uint64_t value)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
}

void
ext_put_64w(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask)
{
    ext_put_header(f, header);
    flex_array_put(f, &value, sizeof value);
    flex_array_put(f, &mask, sizeof mask);
}

          
void
ext_put_64m(struct flex_array *f, uint32_t header, uint64_t value, uint64_t mask)
{
    switch (mask) {
    case 0:
        break;

    case CONSTANT_HTONLL(UINT64_MAX):
        ext_put_64(f, header, value);
        break;

    default:
        ext_put_64w(f, NXM_MAKE_WILD_HEADER(header), value, mask);
        break;
    }
}

void
ext_put_eth(struct flex_array *f, uint32_t header,
            const uint8_t value[ETH_ADDR_LEN])
{
    ext_put_header(f, header);
    flex_array_put(f, value, ETH_ADDR_LEN);
    f->total++;
}

void ext_put_ipv6(struct flex_array *f, uint32_t header,
                    const struct in6_addr *value, const struct in6_addr *mask){
      
    ext_put_header(f, header);
    flex_array_put(f, value, sizeof( struct in6_addr));
    flex_array_put(f, mask, sizeof (struct in6_addr));
    f->total++;
}    

/* TODO: put the ethernet destiny address handling possible masks
static void
ext_put_eth_dst(struct ofpbuf *b,
                uint32_t wc, const uint8_t value[ETH_ADDR_LEN])
{
    switch (wc & (FWW_DL_DST | FWW_ETH_MCAST)) {
    case FWW_DL_DST | FWW_ETH_MCAST:
        break;
    case FWW_DL_DST:
        nxm_put_header(b, NXM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_1, ETH_ADDR_LEN);
        break;
    case FWW_ETH_MCAST:
        nxm_put_header(b, NXM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_0, ETH_ADDR_LEN);
        break;
    case 0:
        nxm_put_eth(b, NXM_OF_ETH_DST, value);
        break;
    }
}*/



