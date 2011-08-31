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
ofl_msg_ext_pack_flow_mod(struct ofl_ext_flow_mod *msg, uint8_t **buf, size_t *buf_len) {
    
    struct ofp_ext_flow_mod *flow_mod;
    uint8_t *ptr;
    int i;

    *buf_len = (sizeof(struct ofp_ext_flow_mod) - 4) + msg->match->length + ofl_structs_instructions_ofp_total_len(msg->instructions, msg->instructions_num, NULL);;
    *buf     = (uint8_t *)malloc(*buf_len);
    
    flow_mod = (struct ofp_ext_flow_mod *)(*buf);
    flow_mod->cookie       = hton64(msg->cookie);
    flow_mod->cookie_mask  = hton64(msg->cookie_mask);
    flow_mod->table_id     =        msg->table_id;
    flow_mod->command      =        msg->command;
    flow_mod->idle_timeout = htons( msg->idle_timeout);
    flow_mod->hard_timeout = htons( msg->hard_timeout);
    flow_mod->priority     = htons( msg->priority);
    flow_mod->buffer_id    = htonl( msg->buffer_id);
    flow_mod->out_port     = htonl( msg->out_port);
    flow_mod->out_group    = htonl( msg->out_group);
    flow_mod->flags        = htons( msg->flags);
    memset(flow_mod->pad,0x00, 2);
    
    ptr = *buf + (sizeof(struct ofp_ext_flow_mod) - 4) ;
    
    flow_mod->match = malloc(msg->match->length);
    ofl_exp_match_pack(msg->match, &(flow_mod->match->header)); 
    memcpy(ptr,&flow_mod->match->header, msg->match->length); 

    ptr +=  msg->match->length;

    for (i=0; i<msg->instructions_num; i++) {

        ptr += ofl_structs_instructions_pack(msg->instructions[i], (struct ofp_instruction *)ptr, NULL);
    }
 
    return 0;
}

int     
ofl_ext_message_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len)    
{

    
        struct ofl_ext_msg_header *exp = (struct ofl_ext_msg_header *)msg;
        int error;
        switch (exp->type) {
            case (EXT_FLOW_MOD):{
                struct ofl_ext_flow_mod *fm = (struct ofl_ext_flow_mod*) exp;
                error = ofl_msg_ext_pack_flow_mod(fm, buf, buf_len);            
            }
            case (EXT_FLOW_REMOVED):{
                //return ofl_msg_ext_pack_flow_removed(exp, buf, buf_len);
                
            }
        
        }
     
     struct ofp_ext_header *oh;    
     oh = (struct ofp_ext_header *)(*buf);

     oh->vendor = htonl(EXTENDED_MATCH_ID);
     oh->subtype = htonl(EXT_FLOW_MOD); 
     return error;
} 

/*
int
ofl_msg_ext_pack_flow_removed(struct ofl_nx_flow_removed *msg, uint8_t **buf, size_t *buf_len) {
    struct nx_flow_removed *ofr;

    *buf_len = sizeof(struct nx_flow_removed);
    *buf     = (uint8_t *)malloc(*buf_len);

    ofr = (struct nx_flow_removed *)(*buf);
    ofr->cookie        = hton64(msg->cookie);
    ofr->priority      = hton64(msg->priority);
    ofr->reason        =        msg->reason;
    ofr->table_id      =        msg->table_id;
    ofr->duration_sec  = htonl( msg->duration_sec);
    ofr->duration_nsec = htonl( msg->duration_nsec);
    ofr->idle_timeout  = htons( msg->idle_timeout);
    memset(ofr->pad, 0x00, 2);
    ofr->packet_count  = hton64(msg->packet_count);
    ofr->byte_count    = hton64(msg->byte_count);

    ofl_exp_match_pack(msg->match, &(ofr->match.header));

    return 0;
}*/
