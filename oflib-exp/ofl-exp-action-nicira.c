#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "ofl-exp-action-nicira.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#define LOG_MODULE ofl_exp_nx
OFL_LOG_INIT(LOG_MODULE)


int
ofl_exp_nicira_action_pack(struct ofl_action_experimenter *action, uint8_t **buf, size_t *buf_len){
}

ofl_err
ofl_exp_nicira_action_unpack(struct ofp_header *oh, size_t *len, struct ofl_action_experimenter **action){
	
}

int
ofl_exp_nicira_action_free(struct ofl_action_experimenter *action){
	
}

char *
ofl_exp_nicira_action_to_string(struct ofl_action_experimenter *action){
	
}