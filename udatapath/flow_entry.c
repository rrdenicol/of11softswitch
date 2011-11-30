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

#include <stdbool.h>
#include <stdlib.h>
#include "datapath.h"
#include "dp_actions.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "flow_hmap.h"
#include "group_table.h"
#include "group_entry.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib-exp/ofl-exp-match.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-utils.h"
#include "bj_hash.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"
#include "match_std.h"
#include "match_ext.h"
#include "nx-match.h"

#include "vlog.h"
#define LOG_MODULE VLM_flow_e

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

struct group_ref_entry {
    struct list node;
    struct group_entry *entry;
};

static void
init_group_refs(struct flow_entry *entry);

static void
del_group_refs(struct flow_entry *entry);

bool
flow_entry_has_out_port(struct flow_entry *entry, uint32_t port) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_port(ia->actions_num, ia->actions, port)) {
                return true;
            }
        }
    }
    return false;
}


bool
flow_entry_has_out_group(struct flow_entry *entry, uint32_t group) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_group(ia->actions_num, ia->actions, group)) {
                return true;
            }
        }
    }
    return false;
}

bool
ext_flow_entry_matches(struct flow_entry *entry, struct ofl_ext_flow_mod *mod, bool strict , bool check_cookie){

     if (check_cookie && ((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask))) {
        return false;
 	 }
    
       if (strict) {
        return (entry->stats->priority == mod->priority) &&
               match_ext_strict((struct ofl_ext_match *)entry->stats->match,
                                (struct ofl_ext_match *)mod->match);
        } else {
        return match_ext_nonstrict((struct ofl_ext_match *)entry->stats->match,
                                   (struct ofl_ext_match *)mod->match);
        }

}

bool
flow_entry_matches(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie) {
    
    if (check_cookie && ((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask))) {
        return false;
 	 }
    
    if (strict) {
        return (entry->stats->priority == mod->priority) &&
               match_std_strict((struct ofl_match_standard *)entry->stats->match,
                                (struct ofl_match_standard *)mod->match);
    } else {
        return match_std_nonstrict((struct ofl_match_standard *)entry->stats->match,
                                   (struct ofl_match_standard *)mod->match);
    }
}


bool
ext_flow_entry_overlaps(struct flow_entry *entry, struct ofl_ext_flow_mod *mod) {
  return (entry->stats->priority == mod->priority &&
            (mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)) &&
            ext_flow_entry_matches(entry, mod, false, true));
}

bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod) {
    return (entry->stats->priority == mod->priority &&
            (mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)) &&
            flow_entry_matches(entry, mod, false, true));
}


void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions) {

    /* TODO Zoltan: could be done more efficiently, but... */
    del_group_refs(entry);

    OFL_UTILS_FREE_ARR_FUN2(entry->stats->instructions, entry->stats->instructions_num,
                            ofl_structs_free_instruction, entry->dp->exp);

    entry->stats->instructions_num = instructions_num;
    entry->stats->instructions     = instructions;

    init_group_refs(entry);
}

bool
flow_entry_idle_timeout(struct flow_entry *entry) {
    bool timeout;

    timeout = (entry->stats->idle_timeout != 0) &&
              (time_msec() > entry->last_used + entry->stats->idle_timeout * 1000);

    if (timeout) {
        flow_entry_remove(entry, OFPRR_IDLE_TIMEOUT);
    }
    return timeout;
}

bool
flow_entry_hard_timeout(struct flow_entry *entry) {
    bool timeout;

    timeout = (entry->remove_at != 0) && (time_msec() > entry->remove_at);

    if (timeout) {
        flow_entry_remove(entry, OFPRR_HARD_TIMEOUT);
    }
    return timeout;
}

void
flow_entry_update(struct flow_entry *entry) {
    entry->stats->duration_sec  =  (time_msec() - entry->created) / 1000;
    entry->stats->duration_nsec = ((time_msec() - entry->created) % 1000) * 1000;
}


/* Creates a modified match from the original match. */
static struct ofl_match_header *
make_mod_match(struct ofl_match_header *match) {
       
    switch (match->type){
        case (OFPMT_STANDARD): {
            struct ofl_match_standard *m = memcpy(xmalloc(OFPMT_STANDARD_LENGTH), match, OFPMT_STANDARD_LENGTH);

            /* NOTE: According to 1.1 spec. only those protocols' fields should be taken into
                     account, which are explicitly matched (MPLS, ARP, IP, TCP, UDP).
                     the rest of the fields are wildcarded in the created match. */


            if ((m->wildcards & OFPFW_DL_TYPE) != 0) {
                m->dl_type = 0x0000;
            }

            /* IPv4 / ARP */
            if (m->dl_type != ETH_TYPE_IP && m->dl_type != ETH_TYPE_ARP) {
                m->nw_tos =               0x00;
                m->nw_proto =             0x0000;
                m->nw_src =               0x00000000;
                m->nw_src_mask =          0xffffffff;
                m->nw_dst =               0x00000000;
                m->nw_dst_mask =          0xffffffff;
                m->wildcards |= OFPFW_NW_TOS;
                m->wildcards |= OFPFW_NW_PROTO;
            }

            /* Transport */
            if (m->nw_proto != IP_TYPE_ICMP && m->nw_proto != IP_TYPE_TCP &&
                m->nw_proto != IP_TYPE_UDP  && m->nw_proto != IP_TYPE_SCTP) {
                m->tp_src =        0x0000;
                m->tp_dst =        0x0000;
                m->wildcards |= OFPFW_TP_SRC;
                m->wildcards |= OFPFW_TP_DST;
            }

            /* MPLS */
            if (m->dl_type != ETH_TYPE_MPLS && m->dl_type != ETH_TYPE_MPLS_MCAST) {
                m->mpls_label = 0x00000000;
                m->mpls_tc =    0x00;
                m->wildcards |= OFPFW_MPLS_LABEL;
                m->wildcards |= OFPFW_MPLS_TC;
            }

            return (struct ofl_match_header *)m;
        }
        case (EXT_MATCH):{
                
                struct ofl_ext_match *m = (struct ofl_ext_match *) match;
                struct flow_hmap *fm = (struct flow_hmap*) malloc(sizeof(struct flow_hmap));
                flow_hmap_init(fm);
                flow_hmap_create(fm, m);
                      
                return (struct ofl_match_header *) fm;
                    
        }
        default: VLOG_WARN_RL(LOG_MODULE, &rl, "Flow entry has unknown match type.");
                return NULL;
    }
}

/* Returns true if the flow entry has a reference to the given group. */
static bool
has_group_ref(struct flow_entry *entry, uint32_t group_id) {
    struct group_ref_entry *g;

    LIST_FOR_EACH(g, struct group_ref_entry, node, &entry->group_refs) {
        if (g->entry->stats->group_id == group_id) {
            return true;
        }
    }
    return false;
}

/* Initializes the group references of the flow entry. */
static void
init_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *e;
    size_t i,j;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            for (j=0; j < ia->actions_num; j++) {
                if (ia->actions[j]->type == OFPAT_GROUP) {
                    struct ofl_action_group *ag = (struct ofl_action_group *)(ia->actions[i]);
                    if (!has_group_ref(entry, ag->group_id)) {
                        struct group_ref_entry *gre = xmalloc(sizeof(struct group_ref_entry));
                        gre->entry = group_table_find(entry->dp->groups, ag->group_id);
                        list_insert(&entry->group_refs, &gre->node);
                    }
                }
            }
        }
    }

    /* notify groups of the new referencing flow entry */
    LIST_FOR_EACH(e, struct group_ref_entry, node, &entry->group_refs) {
        group_entry_add_flow_ref(e->entry, entry);
    }
}

/* Deletes group references from the flow, and also deletes the flow references
 * from the referecenced groups. */
static void
del_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *gre, *next;

    LIST_FOR_EACH_SAFE(gre, next, struct group_ref_entry, node, &entry->group_refs) {
        group_entry_del_flow_ref(gre->entry, entry);
        free(gre);
    }
}

struct flow_entry *
ext_flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_ext_flow_mod *mod) {

    struct flow_entry *entry;
    uint64_t now;

    now = time_msec();

    entry = xmalloc(sizeof(struct flow_entry));
    entry->dp    = dp;
    entry->table = table;

    entry->stats = xmalloc(sizeof(struct ofl_flow_stats));

    entry->stats->table_id         = mod->table_id;
    entry->stats->duration_sec     = 0;
    entry->stats->duration_nsec    = 0;
    entry->stats->priority         = mod->priority;
    entry->stats->idle_timeout     = mod->idle_timeout;
    entry->stats->hard_timeout     = mod->hard_timeout;
    entry->stats->cookie           = mod->cookie;
    entry->stats->packet_count     = 0;
    entry->stats->byte_count       = 0;

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;

    entry->match = make_mod_match(mod->match);
    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout * 1000;
    entry->last_used    = now;
    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);

    list_init(&entry->match_node);
    list_init(&entry->idle_node);
    list_init(&entry->hard_node);

    list_init(&entry->group_refs);
    init_group_refs(entry);

    return entry;
}

struct flow_entry *
flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_msg_flow_mod *mod) {
    struct flow_entry *entry;
    uint64_t now;

    now = time_msec();

    entry = xmalloc(sizeof(struct flow_entry));
    entry->dp    = dp;
    entry->table = table;

    entry->stats = xmalloc(sizeof(struct ofl_flow_stats));

    entry->stats->table_id         = mod->table_id;
    entry->stats->duration_sec     = 0;
    entry->stats->duration_nsec    = 0;
    entry->stats->priority         = mod->priority;
    entry->stats->idle_timeout     = mod->idle_timeout;
    entry->stats->hard_timeout     = mod->hard_timeout;
    entry->stats->cookie           = mod->cookie;
    entry->stats->packet_count     = 0;
    entry->stats->byte_count       = 0;

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;

    entry->match = make_mod_match(mod->match);
    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout * 1000;
    entry->last_used    = now;
    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);

    list_init(&entry->match_node);
    list_init(&entry->idle_node);
    list_init(&entry->hard_node);

    list_init(&entry->group_refs);
    init_group_refs(entry);

    return entry;
}

void
flow_entry_destroy(struct flow_entry *entry) {
    // NOTE: This will be called when the group entry itself destroys the
    //       flow; but it won't be a problem.

    uint16_t type = entry->match->type;
    del_group_refs(entry);
    ofl_structs_free_flow_stats(entry->stats, entry->dp->exp);
    // assumes it is a standard match
    if(type == OFPMT_STANDARD)
        free(entry->match);
    free(entry);
}

void
flow_entry_remove(struct flow_entry *entry, uint8_t reason) {
    
    if (entry->send_removed) {
        flow_entry_update(entry);
        uint16_t type = entry->match->type;
        if (type == OFPMT_STANDARD)
        {
            struct ofl_msg_flow_removed msg =
                    {{.type = OFPT_FLOW_REMOVED},
                     .reason = reason,
                     .stats  = entry->stats};
            dp_send_message(entry->dp, (struct ofl_msg_header *)&msg, NULL);
        }
        else if ( type == EXT_MATCH){
            struct ofl_ext_msg_flow_removed msg =  
            {{{  {.type = OFPT_EXPERIMENTER  },
             .experimenter_id = EXTENDED_MATCH_ID},
             .type =  EXT_FLOW_REMOVED},
             .reason = reason,
             .stats  = entry->stats};
            
            dp_send_message(entry->dp, (struct ofl_msg_header *)&msg, NULL);           
           
            }
    }

    list_remove(&entry->match_node);
    list_remove(&entry->hard_node);
    list_remove(&entry->idle_node);
    entry->table->stats->active_count--;
    flow_entry_destroy(entry);
}
