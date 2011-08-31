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


