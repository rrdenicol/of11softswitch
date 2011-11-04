/* Copyright (c) 2011, CPqD, Brazil
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Eder Leão Fernandes <ederlf@cpqd.com.br>
 */

#include <stdbool.h>
#include <string.h>
#include "lib/bj_hash.h"
#include "lib/nx-match.h"
#include "lib/list_t.h"
#include "match_ext.h"
#include "match_std.h"
#include "nbee_link/nbee_link.h"
#include "oflib-exp/ofl-exp-match.h"

/* Returns true if two values of 8 bit size match, considering their masks. */
static int
sized8_matches(uint8_t *a, uint8_t *am, uint8_t *b) {
     return ((~(am[0]) & (a[0] ^ b[0])) == 0x00);
}     

/* Returns true if two values of 16 bit size match, considering their masks. */
static int
sized16_matches(uint8_t *a, uint8_t *am, uint8_t *b) {

    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask = (uint16_t *) am;
    /* Discover the reason why dl_type is being inverted */
    return (((~*mask) & (ntohs(*a1) ^ *b1)) == 0);
}

/*Returns true if two values of 32 bit size match, considering their masks. */
static int
sized32_matches(uint8_t *a, uint8_t *am, uint8_t *b) {
    
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask = (uint32_t *) am;
    return (((~*mask) & (*a1 ^ *b1)) == 0);
}

/* Returns true if two values of 64 bits size match, considering their masks.*/ 
static int
sized64_matches(uint8_t *a, uint8_t *am, uint8_t *b) {
    
    uint64_t *a1 = (uint64_t *) a; 
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask = (uint64_t *) am;
    
    return (((~*mask) & (*a1 ^ *b1)) == 0);
} 

/* Returns true if the two ethernet addresses match, considering their masks. */
static int
eth_matches(uint8_t *a, uint8_t *am, uint8_t *b) {
     
     return (sized32_matches(a,am,b) && sized16_matches(a+4,am+4,b+4) !=0 );
}

static int
ipv6_matches(uint8_t *a, uint8_t *am, uint8_t *b) {
    

    return (sized64_matches(a,am,b) && sized64_matches(a+8,am+8,b+8) != 0);

}

bool 
packet_match(struct hmap *a, struct hmap *b){

    struct nxm_field *f;
    packet_fields_t *packet_f;
    field_values_t *values;
    bool ret = false;

    HMAP_FOR_EACH(f, struct nxm_field, hmap_node, a){
       
        HMAP_FOR_EACH_WITH_HASH(packet_f, packet_fields_t, hmap_node, hash_int(f->header, 0), b){ 
            ret = true;
            LIST_T_FOR_EACH(values, field_values_t, list_node, &packet_f->fields){
                 
                if (values->len != f->length){
                    return false;     
                }
                
                
                switch (f->length){
                    case (sizeof(uint8_t)):{ 
                        if (sized8_matches(f->value,f->mask, values->value) == 0){
                            return false;
                        }
                        else break;
                    }
                    case (sizeof(uint16_t)):{ 
                         
                        if(sized16_matches(f->value, f->mask, values->value) == 0){
                            return false;
                        }
                        else break;
                        } 
                    case (sizeof(uint32_t)):{ 
                        if(sized32_matches(f->value,f->mask, values->value) == 0)
                            return false;
                        else break;
                        }
                    case (ETHADDLEN):{ 
                        if(eth_matches(f->value, f->mask, values->value ) == 0 )
                            return false;
                        else break;
                        }
                    case (sizeof(uint64_t)):{ 
                        if(eth_matches(f->value,f->mask, values->value) == 0)
                            return false;
                        else break;
                        }
                    case (16):{ 
                        if(ipv6_matches(f->value,  f->mask,values->value) == 0 )
                            return false;
                        else break;
                        }    
                    }
            }
        } 
        if (!ret)
            return ret;
        else ret = false;
        
    }
    
    return true;

}

static inline bool
strict_mask8(uint8_t a, uint8_t b, uint8_t am, uint8_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
	return (am == bm) && ((a ^ b) & ~am) == 0;
}

static inline bool
strict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return strict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
		   strict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));}
		   
		   
static inline bool
strict_ipv6(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask64(*((uint64_t *)a), *((uint64_t *)b), *((uint64_t *)am), *((uint64_t *)bm)) &&
		   strict_mask64(*((uint64_t *)(a+4)), *((uint64_t *)(b+4)), *((uint64_t *)(am+4)), *((uint64_t *)(bm+4)));

}

  /* Terribly inefficient
    Could be done better but... */
bool
match_ext_strict(struct ofl_ext_match *a, struct ofl_ext_match *b) {

  
    int i,j;
    uint8_t * p1 =  a->match_fields.entries;
    uint8_t * p2 =  b->match_fields.entries;
    uint32_t header1, header2;  
    uint8_t found;
    if(a->match_fields.total != b->match_fields.total)
        return false;
    
    for(i = 0; i < a->match_fields.total; i++){
         memcpy(&header1, p1, 4);
         found = 0;
         unsigned int len1 = NXM_LENGTH(header1); 
         for(j = 0; j < b->match_fields.total; j++){     
            memcpy(&header2, p2, 4);
            unsigned int len2 = NXM_LENGTH(header2);
            if (header1 == header2){
                
                found = 1;
                p1 +=4;
                p2 +=4;
                if(NXM_HASMASK(header1) && NXM_HASMASK(header2)){
                    switch(len1){   
                         case (sizeof(uint8_t)):{
                            if(!strict_mask8(*p1, *p2, *(p1 + len1/2), *(p2+len2/2)))
                               return false;
                            break;
                         }
                         case (sizeof(uint16_t)):{
                            if(!strict_mask16(*((uint16_t *)p1), *((uint16_t *)p2), *((uint16_t *)(p1+len1/2)), *((uint16_t *)(p2+len2/2)) ))
                               return false;
                            break;
                         }
                          case (sizeof(uint32_t)):{
                            
                            if(!strict_mask32(*((uint32_t *)p1), *((uint32_t *)p2), *((uint32_t *)(p1+len1/2)), *((uint32_t *)(p2+len2/2)) ))
                               return false;
                            
                            break;
                         }
                          case (ETHADDLEN):{
                            if(!strict_dladdr(p1, p2, p1+len1, p2+len2/2))
                               return false;
                            break;
                         }
                          case (sizeof(uint64_t)):{
                            if(!strict_mask64(*((uint64_t *)p1), *((uint64_t *)p2), *((uint64_t *)(p1+len1/2)), *((uint64_t *)(p2+len2/2)) ))
                               return false;
                               
                            break;
                         } 
                         case (16):{
                            if(!strict_ipv6(p1, p2, p1+len1, p2+len2/2))
                               return false;
                               
                            break;
                         }     
                    }
                    
                    p1 +=len1;
                    p2 =  b->match_fields.entries;
                    break;
                }
              /* We don't have masks, compare only the values */  
                else{  
                    switch(len1){
                         case (sizeof(uint8_t)):{
                            if(!strict_mask8(*p1, *p2, 0x00, 0x00))
                               return false;
                            break;
                         }
                         case (sizeof(uint16_t)):{
                            if(!strict_mask16(*((uint16_t *)p1), *((uint16_t *)p2), 0x0000, 0x0000 )){
                               return false;
                            }
                            break;
                         }
                          case (sizeof(uint32_t)):{
                            
                            if(!strict_mask32(*((uint32_t *)p1), *((uint32_t *)p2), 0x00000000,0x00000000))
                               return false;
                            
                            break;
                         }
                          case (ETHADDLEN):{
                            if(!strict_dladdr(p1, p2, p1+len1, p2+len2))
                               return false;
                            break;
                         }
                          case (sizeof(uint64_t)):{
                            if(!strict_mask64(*((uint64_t *)p1), *((uint64_t *)p2),0x0000000000000000ULL, 0x0000000000000000ULL ))
                               return false;
                               
                            break;
                        }
                    }
                    
                    p1 +=len1;
                    p2 =  b->match_fields.entries;
                    break;
                }
                  
         }
         else {
            p2 += len2 + 4;
            } 
        }
        if (!found)
            return false;
    }
    return true;
    
}      


static inline bool
nonstrict_mask8(uint8_t a, uint8_t b, uint8_t am, uint8_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_mask16(uint16_t a, uint16_t b, uint16_t am, uint16_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_mask32(uint32_t a, uint32_t b, uint32_t am, uint32_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_mask64(uint64_t a, uint64_t b, uint64_t am, uint64_t bm) {
	return (~am & (~a | ~b | bm) & (a | b | bm)) == 0;
}

static inline bool
nonstrict_dladdr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return nonstrict_mask32(*((uint32_t *)a), *((uint32_t *)b), *((uint32_t *)am), *((uint32_t *)bm)) &&
		   nonstrict_mask16(*((uint16_t *)(a+4)), *((uint16_t *)(b+4)), *((uint16_t *)(am+4)), *((uint16_t *)(bm+4)));
}

static inline bool
nonstrict_ipv6(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return nonstrict_mask64(*((uint64_t *)a), *((uint64_t *)b), *((uint64_t *)am), *((uint64_t *)bm)) &&
		   nonstrict_mask64(*((uint64_t *)(a+4)), *((uint64_t *)(b+4)), *((uint64_t *)(am+4)), *((uint64_t *)(bm+4)));
}

/*static inline bool
nonstrict_dlvlan(uint16_t a, uint16_t b, uint32_t aw, uint32_t bw) {
	uint32_t f = OFPFW_DL_VLAN;
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || (a == OFPVID_ANY && b != OFPVID_NONE) || a == b));
}

static inline bool
nonstrict_dlvpcp(uint16_t avlan, uint16_t apcp, uint16_t bvlan, uint16_t bpcp, uint32_t aw, uint32_t bw) {
	uint32_t f = OFPFW_DL_VLAN_PCP;
	return (wc(bw, f) && wc(aw, f)) ||
	      (~wc(bw, f) && (wc(aw, f) || (avlan == OFPVID_NONE && bvlan == OFPVID_NONE) || apcp == bpcp));
}*/




bool
match_ext_nonstrict(struct ofl_ext_match *a, struct ofl_ext_match *b) {
  
   int i,j;
    uint8_t * p1 =  a->match_fields.entries;
    uint8_t * p2 =  b->match_fields.entries;
    uint32_t header1, header2;  
    uint8_t found;
    if(!b->match_fields.total)
        return true; 
    
    if(a->match_fields.total != b->match_fields.total)
        return false;
    
    for(i = 0; i < a->match_fields.total; i++){
         memcpy(&header1, p1, 4);
         found = 0;
         unsigned int len1 = NXM_LENGTH(header1); 
         for(j = 0; j < b->match_fields.total; j++){     
            memcpy(&header2, p2, 4);
            unsigned int len2 = NXM_LENGTH(header2);
            if (header1 == header2){
                
                found = 1;
                p1 +=4;
                p2 +=4;
                if(NXM_HASMASK(header1) && NXM_HASMASK(header2)){
                    switch(len1){   
                         case (sizeof(uint8_t)):{
                            if(!nonstrict_mask8(*p1, *p2, *(p1 + len1/2), *(p2+len2/2)))
                               return false;
                            break;
                         }
                         case (sizeof(uint16_t)):{
                            if(!nonstrict_mask16(*((uint16_t *)p1), *((uint16_t *)p2), *((uint16_t *)(p1+len1/2)), *((uint16_t *)(p2+len2/2)) ))
                               return false;
                            break;
                         }
                          case (sizeof(uint32_t)):{
                            
                            if(!nonstrict_mask32(*((uint32_t *)p1), *((uint32_t *)p2), *((uint32_t *)(p1+len1/2)), *((uint32_t *)(p2+len2/2)) ))
                               return false;
                            
                            break;
                         }
                          case (ETHADDLEN):{
                            if(!nonstrict_dladdr(p1, p2, p1+len1, p2+len2/2))
                               return false;
                            break;
                         }
                          case (sizeof(uint64_t)):{
                            if(!nonstrict_mask64(*((uint64_t *)p1), *((uint64_t *)p2), *((uint64_t *)(p1+len1/2)), *((uint64_t *)(p2+len2/2)) ))
                               return false;
                               
                            break;
                         } 
                         case (16):{
                            if(!nonstrict_ipv6(p1, p2, p1+len1, p2+len2/2))
                               return false;
                               
                            break;
                         }     
                    }
                    
                    p1 +=len1;
                    p2 =  b->match_fields.entries;
                    break;
                }
              /* We don't have masks, compare only the values */  
                else{  
                    switch(len1){
                         case (sizeof(uint8_t)):{
                            if(!strict_mask8(*p1, *p2, 0x00, 0x00))
                               return false;
                            break;
                         }
                         case (sizeof(uint16_t)):{
                            if(!nonstrict_mask16(*((uint16_t *)p1), *((uint16_t *)p2), 0x0000, 0x0000 )){
                               return false;
                            }
                            break;
                         }
                          case (sizeof(uint32_t)):{
                            
                            if(!nonstrict_mask32(*((uint32_t *)p1), *((uint32_t *)p2), 0x00000000,0x00000000))
                               return false;
                            
                            break;
                         }
                          case (ETHADDLEN):{
                            if(!nonstrict_dladdr(p1, p2, p1+len1, p2+len2))
                               return false;
                            break;
                         }
                          case (sizeof(uint64_t)):{
                            if(!nonstrict_mask64(*((uint64_t *)p1), *((uint64_t *)p2),0x0000000000000000ULL, 0x0000000000000000ULL ))
                               return false;
                               
                            break;
                        }
                    }
                    
                    p1 +=len1;
                    p2 =  b->match_fields.entries;
                    break;
                }
                  
         }
         else {
            p2 += len2 + 4;
            } 
        }
        if (!found)
            return false;
    }
    return true;  


}

