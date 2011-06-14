#ifndef OFL_EXP_MATCH_NICIRA_H
#define OFL_EXP_MATCH_NICIRA_H 1


#include "../oflib/ofl-structs.h"

struct ofl_exp_nicira_match_header {
    struct ofl_match_experimenter   header; 
    uint32_t   type;

};




int
ofl_exp_nicira_match_pack(struct ofl_match_experimenter *msg, uint8_t **buf, size_t *buf_len);

ofl_err
ofl_exp_nicira_match_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg);

int
ofl_exp_nicira_match_free(struct ofl_match_experimenter *msg);

char *
ofl_exp_nicira_match_to_string(struct ofl_match_experimenter *msg);


#endif /* OFL_EXP_MATCH_NICIRA_H */