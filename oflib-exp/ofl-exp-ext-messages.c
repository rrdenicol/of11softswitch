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

static void
ofl_ext_flow_stats_print(FILE *stream, struct ofl_flow_stats *s) {
    size_t i;

    fprintf(stream, "{table=\"");
    ofl_table_print(stream, s->table_id);
    fprintf(stream, "\", match=\"");
    ofl_exp_match_print(stream, s->match);
    fprintf(stream, "\", dur_s=\"%u\", dur_ns=\"%u\", prio=\"%u\", "
                          "idle_to=\"%u\", hard_to=\"%u\", cookie=\"0x%"PRIx64"\", "
                          "pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", insts=[",
                  s->duration_sec, s->duration_nsec, s->priority,
                  s->idle_timeout, s->hard_timeout, s->cookie,
                  s->packet_count, s->byte_count);

    for (i=0; i<s->instructions_num; i++) {
        ofl_structs_instruction_print(stream, s->instructions[i], NULL);
        if (i < s->instructions_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}");
}


void
ofl_ext_msg_print_stats_reply_flow(struct ofl_msg_stats_reply_experimenter *msg, FILE *stream) {
    size_t i;

    struct ofl_flow_stats **stats = (struct ofl_flow_stats **) msg->data;
    fprintf(stream, ", ext_flow_stats=[");
    for (i=0; i<msg->data_length; i++) {
       
        ofl_ext_flow_stats_print(stream, stats[i]);
        if (i < msg->data_length - 1) { fprintf(stream, "\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_ext_free_flow_stats(struct ofl_flow_stats *stats) {
    OFL_UTILS_FREE_ARR_FUN2(stats->instructions, stats->instructions_num,
                            ofl_structs_free_instruction, NULL);
    ofl_exp_match_free(stats->match);
    free(stats);
}

void
ofl_ext_stats_req_print(struct ofl_ext_flow_stats_request *msg, FILE *stream)
{

    fprintf(stream, ", table=\"");
    ofl_table_print(stream, msg->table_id);
    fprintf(stream, "\", oport=\"");
    ofl_port_print(stream, msg->out_port);
    fprintf(stream, "\", ogrp=\"");
    ofl_group_print(stream, msg->out_group);
    fprintf(stream, "\", cookie=0x%"PRIx64"\", mask=0x%"PRIx64"\", match=",
                  msg->cookie, msg->cookie_mask);
    if (msg->match != NULL)
        ofl_exp_match_print(stream, msg->match);

}

char *
ofl_ext_message_to_string(struct ofl_msg_experimenter *msg){

    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    if (msg->experimenter_id == EXTENDED_MATCH_ID) {
        struct ofl_ext_msg_header *exp = (struct ofl_ext_msg_header *) msg;
        switch (exp->type){
            case (EXT_FLOW_MOD):{
                size_t i;
                struct ofl_ext_flow_mod *fm = (struct ofl_ext_flow_mod*) exp;
                fprintf(stream, "_flow_mod");
                fprintf(stream, "{table=\"");
                ofl_table_print(stream, fm->table_id);
                fprintf(stream, "\", cmd=\"");
                ofl_flow_mod_command_print(stream, fm->command);
                fprintf(stream, "\", cookie=\"0x%"PRIx64"\", mask=\"0x%"PRIx64"\", "
                          "idle=\"%u\", hard=\"%u\", prio=\"%u\", buf=\"",
                fm->cookie, fm->cookie_mask,
                fm->idle_timeout, fm->hard_timeout, fm->priority);
                ofl_buffer_print(stream, fm->buffer_id);
                fprintf(stream, "\", port=\"");
                ofl_port_print(stream, fm->out_port);
                fprintf(stream, "\", group=\"");
                ofl_group_print(stream, fm->out_group);
                fprintf(stream, "\", flags=\"0x%"PRIx16"\", match=",fm->flags);
                if(fm->match != NULL){
            
                    ofl_exp_match_print(stream, fm->match);
                    
                    }
                fprintf(stream, ", insts=[");

                for(i=0; i<fm->instructions_num; i++) {
                    ofl_structs_instruction_print(stream, fm->instructions[i], NULL);
                    if (i < fm->instructions_num - 1) { fprintf(stream, ", "); }
                }
                fprintf(stream, "]}");
                  
                break;
            }
            case (EXT_FLOW_REMOVED):{
                    struct ofl_ext_msg_flow_removed * fr =  (struct ofl_ext_msg_flow_removed *) msg;
                    fprintf(stream, "{reas=\"");
                    ofl_flow_removed_reason_print(stream, fr->reason);
                    fprintf(stream, "\", stats=");
                    ofl_ext_flow_stats_print(stream, fr->stats);
                    fprintf(stream, "}");          
            }
        
        }
       
    }
    fclose(stream);
    return str;
}

int
ofl_ext_msg_free(struct ofl_msg_experimenter *msg){

     if (msg->experimenter_id == EXTENDED_MATCH_ID) {
         struct ofl_ext_msg_header *exp = (struct ofl_ext_msg_header *) msg;
         free(exp);  
         
    }
    else OFL_LOG_WARN(LOG_MODULE, "Trying to free non-Extended-Match Experimenter message.");
    return 0;  
}

int
ofl_ext_free_flow_mod(struct ofl_ext_flow_mod *msg, bool with_match, bool with_instructions, struct ofl_exp *exp) {
    if (with_match) {
        ofl_structs_free_match(msg->match, exp);
    }
    if (with_instructions) {
        OFL_UTILS_FREE_ARR_FUN2(msg->instructions, msg->instructions_num,
                                ofl_structs_free_instruction, exp);
    }

    free(msg);
    return 0;
}

ofl_err
ofl_utils_count_ofp_ext_flow_stats(void *data, size_t data_len, size_t *count) {
    struct ofp_ext_flow_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_ext_flow_stats)) {
        stat = (struct ofp_ext_flow_stats *) d;
        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_ext_flow_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received flow stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;

}

int ofl_ext_stats_reply_free(struct ofl_msg_stats_reply_header *msg){

    int i;
    struct ofl_flow_stats **stats;
    struct ofl_msg_stats_reply_experimenter *exp_st = (struct ofl_msg_stats_reply_experimenter *)msg;
    stats = (struct ofl_flow_stats **) exp_st->data;
    for (i = 0; i < exp_st->data_length; i++ ){    
        ofl_ext_free_flow_stats(stats[i]);
    }
    return 0;    
                                
}

int
ofl_ext_free_flow_removed(struct ofl_msg_flow_removed *msg, bool with_stats, struct ofl_exp *exp) {
    if (with_stats) {
        ofl_structs_free_flow_stats(msg->stats, exp);
    }
    free(msg);
    return 0;
}

int
ofl_ext_free_stats_req_flow(struct ofl_ext_flow_stats_request *req){

    ofl_exp_match_free(req->match);
    free(req);
    return 0;

}
