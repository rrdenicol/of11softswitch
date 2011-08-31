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
           // return ofl_ext_unpack_flow_removed(oh, len, msg);
        
        }
   }
   return 0;
}

ofl_err
ofl_ext_unpack_flow_mod(struct ofp_header *src, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_ext_flow_mod *sm;
    struct ofl_ext_flow_mod *dm;
    struct ofp_instruction *inst;
    ofl_err error;
    size_t i;
    
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


    uint8_t *buff = src;
    buff += (sizeof(struct ofp_ext_flow_mod) -4);
    struct ext_match *match;
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

/*
ofl_err
ofl_ext_unpack_flow_removed(struct ofp_header *src, size_t *len, struct ofl_msg_experimenter **msg) {
    struct nx_flow_removed *sr;
    struct ofl_nx_flow_removed *dr;
    ofl_err error;

    /*if (*len < (sizeof(struct ofp_flow_removed) - sizeof(struct ofp_match))) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid length (%zu).", *len);
        return OFL_ERROR;
    }*

    sr = (struct nx_flow_removed *)src;

    if (sr->table_id == 0xff) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(sr->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }
    *len -= (sizeof(struct nx_flow_removed) - sizeof(struct ofp_match));

    dr = (struct ofl_nx_flow_removed *)malloc(sizeof(struct ofl_nx_flow_removed));
    dr->reason = (enum ofp_flow_removed_reason)sr->reason;

    dr->table_id         =        sr->table_id;
    dr->duration_sec     = ntohl( sr->duration_sec);
    dr->duration_nsec    = ntohl( sr->duration_nsec);
    dr->priority         = ntoh64(sr->priority);
    dr->idle_timeout     = ntohs( sr->idle_timeout);
    dr->cookie           = ntoh64(sr->cookie);
    dr->packet_count     = ntoh64(sr->packet_count);
    dr->byte_count       = ntoh64(sr->byte_count);

    error = ofl_exp_match_unpack(&(sr->match.header), len, &(dr->match));
    if (error) {
        free(dr->match);
        free(dr);
        return error;
    }
    *msg = (struct ofl_msg_header *)dr;
    return 0;
}*/




