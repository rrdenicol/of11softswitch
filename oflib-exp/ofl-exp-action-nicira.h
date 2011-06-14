#ifndef OFL_EXP_ACTION_NICIRA_H
#define OFL_EXP_ACTION_NICIRA_H 1


#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-actions.h" 

struct ofl_exp_nicira_action_header {
    struct ofl_action_experimenter   header;
    
    uint32_t   type;
};

/* TODO change ofl_action_experimenter to action */
int
ofl_exp_nicira_action_pack(struct ofl_action_experimenter *action, uint8_t **buf, size_t *buf_len);

ofl_err
ofl_exp_nicira_action_unpack(struct ofp_header *oh, size_t *len, struct ofl_action_experimenter **action);

int
ofl_exp_nicira_action_free(struct ofl_action_experimenter *action);

char *
ofl_exp_nicira_action_to_string(struct ofl_action_experimenter *action);


#endif /* OFL_EXP_ACTION_NICIRA_H */