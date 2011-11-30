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
 
#include <stdio.h> 
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <endian.h>

#include "../include/openflow/match-ext.h"
#include "ofl-exp-match.h"
#include "ofl-exp-ext-messages.h"
#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-log.h"
#include "../oflib/ofl-utils.h"
#include "../oflib/ofl-print.h"

#define LOG_MODULE ofl_exp
OFL_LOG_INIT(LOG_MODULE)

int
ofl_ext_message_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg){
    
    struct ofp_ext_header *h; 
    h = (struct ofp_ext_header *) oh;
    switch(ntohl(h->subtype)){
        case(EXT_FLOW_MOD):{
            return ofl_ext_unpack_flow_mod(oh, len, msg);
        }
        case(EXT_FLOW_REMOVED):{
           return ofl_ext_unpack_flow_removed(oh, len, msg);
        }

   }
   return 0;
}

ofl_err
ofl_ext_unpack_flow_mod(struct ofp_header *src, size_t *len, struct ofl_msg_experimenter **msg) {
    
    struct ofp_ext_flow_mod *sm;
    struct ofl_ext_flow_mod *dm;
    struct ofp_instruction *inst;
    struct ext_match *match;
    ofl_err error;
    size_t i;
    uint8_t * buff;
    
    sm = (struct ofp_ext_flow_mod *) src;
    
    
     if (*len < ((sizeof(struct ofp_ext_flow_mod)) - sizeof(struct ext_match) )) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_MOD message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
     }

    *len -= (sizeof(struct ofp_ext_flow_mod) - 4) ;
    
    dm = (struct ofl_ext_flow_mod *)malloc(sizeof(struct ofl_ext_flow_mod) );
    dm->header.type = ntohl(sm->header.subtype);
    dm->header.header.experimenter_id =  ntohl(sm->header.vendor);
    dm->cookie =       ntoh64(sm->cookie);
    dm->cookie_mask =  ntoh64(sm->cookie_mask);
    dm->table_id =     sm->table_id;
    dm->command =      (enum ofp_flow_mod_command)sm->command;
    dm->idle_timeout = ntohs( sm->idle_timeout);
    dm->hard_timeout = ntohs( sm->hard_timeout);
    dm->priority =     ntohs( sm->priority);
    dm->buffer_id =    ntohl( sm->buffer_id);
    dm->out_port =     ntohl( sm->out_port);
    dm->out_group =    ntohl( sm->out_group);
    dm->flags =        ntohs( sm->flags);

 
    buff = (uint8_t*) src;
    buff += (sizeof(struct ofp_ext_flow_mod) -4);

    match = (struct ext_match *) buff;    

    error = ofl_exp_match_unpack(&(match->header), len, &(dm->match));
    if (error) {
        free(dm);
        return error;
    }

    buff +=  ntohs(match->header.length);

    error = ofl_utils_count_ofp_instructions(buff, *len, &dm->instructions_num);
    if (error) {
        ofl_exp_match_free(dm->match);
        free(dm);
        return error;
    }
    
    dm->instructions = (struct ofl_instruction_header **)malloc(dm->instructions_num * sizeof(struct ofl_instruction_header *));
    inst = (struct ofp_instruction *) buff;
    for (i = 0; i < dm->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, len, &(dm->instructions[i]), NULL);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->instructions, i,
                    ofl_structs_free_instruction, NULL);
            ofl_structs_free_match(dm->match, NULL);
            free(dm);
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }
   
    *msg = (struct ofl_msg_experimenter *)dm;
    return 0;
}


ofl_err
ofl_ext_unpack_stats_request_flow(struct ofp_stats_request *os, size_t *len, struct ofl_msg_header **msg) {
    
    struct ofp_ext_flow_stats_request *sm;
    struct ofl_ext_flow_stats_request *dm;
    ofl_err error = 0;

    // ofp_stats_request length was checked at ofl_msg_unpack_stats_request
    sm = (struct ofp_ext_flow_stats_request *)os->body;
    if (*len < ((sizeof(struct ofp_ext_flow_mod)) - sizeof(struct ext_match) )) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW stats request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    
    *len -= (sizeof(struct ofp_ext_flow_stats_request) - sizeof(struct ext_match)) ;
    dm = (struct ofl_ext_flow_stats_request *) malloc(sizeof(struct ofl_ext_flow_stats_request));
    
    dm->table_id = sm->table_id;
    dm->out_port = ntohl(sm->out_port);
    dm->out_group = ntohl(sm->out_group);
    dm->cookie = ntoh64(sm->cookie);
    dm->cookie_mask = ntoh64(sm->cookie_mask);
    
    error = ofl_exp_match_unpack(&(sm->match.header), len, &(dm->match));
    memcpy(&dm->header.experimenter_id,os->pad, sizeof(dm->header.experimenter_id));
    if (error) {
        free(dm);
        return error;
    }
    *msg = (struct ofl_msg_header *)dm;
     
         
    return 0;
}

static ofl_err
ofl_ext_flow_stats_unpack(uint8_t *stats, size_t *len, struct ofl_flow_stats **dst){

    struct ofp_ext_flow_stats *src;
    struct ofl_flow_stats *s;
    struct ofp_instruction *inst; 
    struct ext_match *match;
    ofl_err error;
    size_t i;
   

    src = (struct ofp_ext_flow_stats*) stats;
    match = (struct ext_match*) (stats + (sizeof(struct ofp_ext_flow_stats) -4));
   
    if (*len < ((sizeof(struct ofp_ext_flow_stats)) - sizeof(struct ext_match) )) {
         OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid length (%zu).", *len);
         return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    

    if (src->table_id == 0xff) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    
   
    stats += (sizeof(struct ofp_ext_flow_stats) -4 );
    *len -= (sizeof(struct ofp_ext_flow_stats) -4 );

    s = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));

    s->table_id =             src->table_id;
    s->duration_sec =  ntohl( src->duration_sec);
    s->duration_nsec = ntohl( src->duration_nsec);
    s->priority =      ntohs( src->priority);
    s->idle_timeout =  ntohs( src->idle_timeout);
    s->hard_timeout =  ntohs( src->hard_timeout);
    s->cookie =        ntoh64(src->cookie);
    s->packet_count =  ntoh64(src->packet_count);
    s->byte_count =    ntoh64(src->byte_count);
    s->match = malloc(ntohs(match->header.length));
    error = ofl_exp_match_unpack(&(match->header), len, &(s->match));
    if (error) {
        free(s);
        return error;
    }
   
    stats +=  ntohs(match->header.length);
    error = ofl_utils_count_ofp_instructions(stats, *len, &s->instructions_num);
    if (error) {
        ofl_exp_match_free(s->match);
        free(s);
        return error;
    }
    s->instructions = (struct ofl_instruction_header **)malloc(s->instructions_num * sizeof(struct ofl_instruction_header *));

    inst = (struct ofp_instruction *) stats;

    for (i = 0; i < s->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, len, &(s->instructions[i]), NULL);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(s->instructions, i,
                                    ofl_structs_free_instruction, NULL);
            free(s);
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }
     
    *dst = s;

    return 0;

}

ofl_err
ofl_ext_unpack_stats_reply(struct ofp_stats_reply *os, size_t *len, struct ofl_msg_stats_reply_header **msg) {
    struct ofp_ext_flow_stats *stat;
    struct ofl_msg_stats_reply_experimenter *dm;
    struct ofl_flow_stats ** st_dst;
    ofl_err error;
    size_t i,pos;
    size_t * flow_stats_len = malloc (sizeof (size_t));

    // ofp_stats_reply was already checked and subtracted in unpack_stats_reply
    
    stat = (struct ofp_ext_flow_stats *)os->body;
    dm = (struct ofl_msg_stats_reply_experimenter *)malloc(sizeof(struct ofl_msg_stats_reply_experimenter ));
    error = ofl_utils_count_ofp_ext_flow_stats(stat, *len, &dm->data_length);
    if (error) {
        free(dm);
        return error;
    }
    dm->data = (uint8_t*) malloc(dm->data_length * sizeof(struct ofl_ext_flow_stats *));
    st_dst = (struct ofl_flow_stats **) dm->data;
    
    pos = 0;
    
    for (i = 0; i < dm->data_length; i++) {
        *flow_stats_len = ntohs(stat->length);
        *len -= *flow_stats_len;
        error = ofl_ext_flow_stats_unpack((uint8_t*) stat + pos, flow_stats_len, &(st_dst[i]));
        pos +=   *flow_stats_len;
        
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2((struct ofl_flow_stats *) &dm->data, i,
                                    ofl_structs_free_flow_stats, NULL);
            free (dm);
            return error;
        }
        stat = (struct ofp_ext_flow_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;  
   
}

ofl_err
ofl_ext_unpack_flow_removed(struct ofp_header *src, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_ext_flow_removed *sr;
    struct ofl_ext_msg_flow_removed *dr;
    ofl_err error;

    sr = (struct ofp_ext_flow_removed *)src;
    
    if (*len < ((sizeof(struct ofp_ext_flow_removed)) - sizeof(struct ext_match) )) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid length (%zu).", *len);
        return OFL_ERROR;
    }
    
    
    if (sr->table_id == 0xff) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(sr->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }
    *len -= (sizeof(struct ofp_ext_flow_removed) -sizeof(struct ext_match));
    
    dr = (struct ofl_ext_msg_flow_removed *)malloc(sizeof(struct ofl_ext_msg_flow_removed));
    dr->header.type = ntohl(sr->header.subtype);
    dr->header.header.experimenter_id =  ntohl(sr->header.vendor);
    dr->reason = (enum ofp_flow_removed_reason)sr->reason;

    dr->stats = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
    dr->stats->table_id         =        sr->table_id;
    dr->stats->duration_sec     = ntohl( sr->duration_sec);
    dr->stats->duration_nsec    = ntohl( sr->duration_nsec);
    dr->stats->priority         = ntoh64(sr->priority);
    dr->stats->idle_timeout     = ntohs( sr->idle_timeout);
    dr->stats->hard_timeout     = 0;
    dr->stats->cookie           = ntoh64(sr->cookie);
    dr->stats->packet_count     = ntoh64(sr->packet_count);
    dr->stats->byte_count       = ntoh64(sr->byte_count);
    dr->stats->instructions_num = 0;
    dr->stats->instructions     = NULL;

    error = ofl_exp_match_unpack(&(sr->match.header), len, &(dr->stats->match));
    if (error) {
        free(dr->stats);
        free(dr);
        return error;
    }

    *msg = (struct ofl_msg_experimenter *)dr;
    return 0;
}
