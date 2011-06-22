#ifndef OFL_EXP_MATCH_H
#define OFL_EXP_MATCH_H 1

#include <sys/types.h>
#include <stdio.h>

#include "openflow/openflow.h"
#include "openflow/match-ext.h"
#include "lib/ofl-structs.h"
#include "ofl.h"

struct ofl_exp_match {

    struct ofl_match_header header      /* One of OFPMT_* */
    uint16_t length;                    /* Length of ofp_match */
    uint32_t wildcards;                 /* Wildcard fields. */
    struct flex_array *match_fields;    /* Match fields */   
}


size_t
ofl_exp_match_pack(struct ofl_match_header *src, struct ofp_match *dst, struct ofl_exp *exp);

ofl_err
ofl_exp_match_unpack(struct ofp_match *src, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp);

int     
ofl_exp_match_free(struct ofl_match_header *m);
    
size_t  
ofl_exp_match_len(struct ofl_match_header *m);

char   
ofl_exp_match_to_str(struct ofl_match_header *m);

#endif /* OFL_EXP_MATCH_H */
