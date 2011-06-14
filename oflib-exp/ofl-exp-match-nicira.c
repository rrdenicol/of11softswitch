#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "ofl-exp-match-nicira.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#define LOG_MODULE ofl_exp_nx
OFL_LOG_INIT(LOG_MODULE)

/* TODO change ofl_msg_experimenter to match */
int
ofl_exp_nicira_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len){
	
	 // if (msg->experimenter_id == NX_VENDOR_ID) {
	//	     struct ofl_exp_nicira_match_header *exp = (struct ofl_exp_nicira_match_header *)msg;
		     
		  
		  
		  
		  
	  //}
	
}

ofl_err
ofl_exp_nicira_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg){
	
}

int
ofl_exp_nicira_msg_free(struct ofl_msg_experimenter *msg){
	
}

char *
ofl_exp_nicira_msg_to_string(struct ofl_msg_experimenter *msg){
	
}