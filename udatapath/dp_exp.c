/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
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
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <string.h>
#include "datapath.h"
#include "dp_exp.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "oflib-exp/ofl-exp-ext-messages.h"
#include "oflib-exp/ofl-exp-match.h"
#include "openflow/openflow.h"
#include "openflow/openflow-ext.h"
#include "openflow/match-ext.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

#define LOG_MODULE VLM_dp_exp

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

void
dp_exp_action(struct packet * pkt UNUSED, struct ofl_action_experimenter *act) {
	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter action (%u).", act->experimenter_id);
}

void
dp_exp_inst(struct packet *pkt UNUSED, struct ofl_instruction_experimenter *inst) {
	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter instruction (%u).", inst->experimenter_id);
}

ofl_err
dp_exp_stats(struct datapath *dp UNUSED,
                                  struct ofl_msg_stats_request_experimenter *msg,
                                  const struct sender *sender UNUSED) {
    
    switch (msg->experimenter_id) {
        case (EXTENDED_MATCH_ID): {  
            struct ofl_msg_stats_request_header *req = (struct  ofl_msg_stats_request_header *) msg;
            
            switch (req->type){
                case (OFPST_EXPERIMENTER):{
                    return pipeline_ext_handle_stats_request_flow(dp->pipeline, (struct ofl_ext_flow_stats_request *)msg, sender);                
                
                
                }
            
            }
        
        
        }
    }                            
    
	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter stats (%u).", msg->experimenter_id);
    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
}


ofl_err
dp_exp_message(struct datapath *dp,
                                struct ofl_msg_experimenter *msg,
                               const struct sender *sender) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;

            switch(exp->type) {
                case (OFP_EXT_QUEUE_MODIFY): {
                    return dp_ports_handle_queue_modify(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_QUEUE_DELETE): {
                    return dp_ports_handle_queue_delete(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_SET_DESC): {
                    return dp_handle_set_desc(dp, (struct ofl_exp_openflow_msg_set_dp_desc *)msg, sender);
                }
                default: {
                	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter type (%u).", exp->type);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_SUBTYPE);
                }
            }
        }

        case (NX_VENDOR_ID): {
            struct ofl_exp_nicira_msg_header *exp = (struct ofl_exp_nicira_msg_header *)msg;

            switch (exp->type) {
                case (NXT_ROLE_REQUEST): {
                    return dp_handle_nx_role(dp, (struct ofl_exp_nicira_msg_role *)msg, sender);
                }
            }
        }
	    case (EXTENDED_MATCH_ID):{
	        struct ofl_ext_msg_header *exp = (struct ofl_ext_msg_header *)msg;
	        
	        switch (exp->type){
	            case (EXT_FLOW_MOD): {
	                struct ofl_ext_flow_mod *fm =  (struct ofl_ext_flow_mod *) exp;
	                pipeline_handle_ext_flow_mod(dp->pipeline, fm, sender);
                    /*struct ofl_ext_match *match = (struct ofl_ext_match *) fm->match;
                    struct ofl_instruction_header *inst = (struct ofl_instruction_header *) *fm->instructions;
                    uint8_t *x = match->match_fields.entries;
                    uint32_t *p = x + 10;
                    printf("MATCH %x\n", *p); */
	                /*Return the Extended Flow Mod handler */
	                return 0;
	            }
	        
	        }
	   }

        default: {
	     VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter id (%u).", msg->experimenter_id);
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}
