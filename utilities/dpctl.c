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

#include <config.h>
#include <arpa/inet.h>

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "dpctl.h"
#include "nx-match.h"
#include "flex-array.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl.h"
#include "oflib-exp/ofl-exp.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib-exp/ofl-exp-match.h"
#include "oflib-exp/ofl-exp-ext-messages.h"

#include "command-line.h"
#include "compiler.h"
#include "dpif.h"
#include "openflow/nicira-ext.h"
#include "openflow/match-ext.h"
#include "openflow/openflow-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "ipv6_util.h"
#include "random.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"

#include "xtoxll.h"
#include "ofpstat.h"
#include "openflow/private-ext.h"

#include "vlog.h"

#define LOG_MODULE VLM_dpctl


// NOTE: the request and the barrier is sent with the same xid,
//       so a vconn_receive_block will return with either the
//       response, barrier resp., or the error
#define XID   0xf0ff00f0


struct command {
    char *name;
    int min_args;
    int max_args;
    void (*handler)(struct vconn *vconn, int argc, char *argv[]);
};

static struct command all_commands[];

static int preferred_flow_format = 0;

static void
usage(void) NO_RETURN;

static void
parse_options(int argc, char *argv[]);

static uint8_t mask_all[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


static void 
parse_ext_flow_mod_args(char *str,  struct ofl_ext_flow_mod *req);

static void
parse_flow_mod_args(char *str,  struct ofl_msg_flow_mod  *req);

static void
parse_group_mod_args(char *str, struct ofl_msg_group_mod *req);

static void
parse_bucket(char *str, struct ofl_bucket *b);

static void
parse_ext_flow_stat_args(char *str, struct ofl_ext_flow_stats_request *req);

static void
parse_flow_stat_args(char *str, struct ofl_msg_stats_request_flow *req);

static void
parse_match(char *str, struct ofl_match_header **match, int flow_format);

static void
parse_inst(char *str, struct ofl_instruction_header **inst);

static void
parse_actions(char *str, size_t *acts_num, struct ofl_action_header ***acts);

static void
parse_config(char *str, struct ofl_config *config);

static void
parse_port_mod(char *str, struct ofl_msg_port_mod *msg);

static void
parse_table_mod(char *str, struct ofl_msg_table_mod *msg);


static void
make_all_match(struct ofl_match_header **match);

static void
make_ext_all_match(struct ofl_match_header **match);


static int
parse_port(char *str, uint32_t *port);


static int
parse_queue(char *str, uint32_t *port);

static int
parse_group(char *str, uint32_t *group);

static int
parse_table(char *str, uint8_t *table);

static int
parse_dl_addr(char *str, uint8_t *addr);

static int
parse_nw_addr(char *str, uint32_t *addr);

static int
parse_vlan_vid(char *str, uint16_t *vid);


static int
parse8(char *str, struct names8 *names, size_t names_num, uint8_t max, uint8_t *val);

static int
parse16(char *str, struct names16 *names, size_t names_num, uint16_t max, uint16_t *val);

static int
parse32(char *str, struct names32 *names, size_t names_num, uint32_t max, uint32_t *val);


int
ofputil_flow_format_from_string(const char *s);

const char *
ofputil_flow_format_to_string(enum ofp_ext_flow_format flow_format);

static struct ofl_exp_stats dpctl_exp_stats = 
        {.req_pack      = ofl_exp_req_pack,
         .req_unpack    = ofl_exp_req_unpack,
         .req_free      = ofl_exp_free_stats_req,
         .req_to_string = ofl_req_to_string,
         .reply_pack    = ofl_exp_reply_pack,
         .reply_unpack  = ofl_exp_reply_unpack,
         .reply_free    = ext_free_stats_reply,
         .reply_to_string     = ext_reply_to_string };

static struct ofl_exp_msg dpctl_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

static struct ofl_exp_match dpctl_exp_match =
        {.pack      = ofl_exp_match_pack,
         .unpack    = ofl_exp_match_unpack,
         .free      = ofl_exp_match_free,
         .ofp_len   = ofl_exp_match_length,
         .to_string = ofl_exp_match_to_string};

static struct ofl_exp dpctl_exp =
        {.act   = NULL,
         .inst  = NULL,
         .match = &dpctl_exp_match,
         .stats = &dpctl_exp_stats,
         .msg   = &dpctl_exp_msg};

static void
dpctl_transact(struct vconn *vconn, struct ofl_msg_header *req,
                              struct ofl_msg_header **repl) {
    struct ofpbuf *ofpbufreq, *ofpbufrepl;
    uint8_t *bufreq;
    size_t bufreq_size;
    int error;
     
    error = ofl_msg_pack(req, XID, &bufreq, &bufreq_size, &dpctl_exp);
   
    if (error) {
        ofp_fatal(0, "Error packing request.");
    }


    ofpbufreq = ofpbuf_new(0);
    ofpbuf_use(ofpbufreq, bufreq, bufreq_size);
    ofpbuf_put_uninit(ofpbufreq, bufreq_size);
    error = vconn_transact(vconn, ofpbufreq, &ofpbufrepl);
    if (error) {
        ofp_fatal(0, "Error during transaction.");
    }
    error = ofl_msg_unpack(ofpbufrepl->data, ofpbufrepl->size, repl, NULL /*xid_ptr*/, &dpctl_exp);

    if (error) {
        ofp_fatal(0, "Error unpacking reply.");
    }

    /* NOTE: if unpack was successful, message takes over ownership of buffer's
     *       data. Rconn and vconn does not allocate headroom, so the ofpbuf
     *       wrapper can simply be deleted, keeping the data for the message. */
    ofpbufrepl->base = NULL;
    ofpbufrepl->data = NULL;
    ofpbuf_delete(ofpbufrepl);
}

static void
dpctl_transact_and_print(struct vconn *vconn, struct ofl_msg_header *req,
                                        struct ofl_msg_header **repl) {
    struct ofl_msg_header *reply;
    char *str;
    
    str = ofl_msg_to_string(req, &dpctl_exp);
    printf("\nSENDING:\n%s\n\n", str);
    free(str);
    dpctl_transact(vconn, req, &reply);
    
    str = ofl_msg_to_string(reply, &dpctl_exp);
    printf("\nRECEIVED:\n%s\n\n", str);
    free(str);

    if (repl != NULL) {
        (*repl) = reply;
    } else {
        ofl_msg_free(reply, &dpctl_exp);
    }
}

static void
dpctl_barrier(struct vconn *vconn) {
    struct ofl_msg_header *reply;
    char *str;

    struct ofl_msg_header req =
            {.type = OFPT_BARRIER_REQUEST};
    dpctl_transact(vconn, &req, &reply);
    if (reply->type == OFPT_BARRIER_REPLY) {
        str = ofl_msg_to_string(reply, &dpctl_exp);
        printf("\nOK.\n\n");
        free(str);
    } else {
        str = ofl_msg_to_string(reply, &dpctl_exp);
        printf("\nRECEIVED:\n%s\n\n", str);
        free(str);
    }

}

static void
dpctl_send(struct vconn *vconn, struct ofl_msg_header *msg) {
    struct ofpbuf *ofpbuf;
    uint8_t *buf;
    size_t buf_size;
    int error;
    error = ofl_msg_pack(msg, XID, &buf, &buf_size, &dpctl_exp);
    if (error) {
        ofp_fatal(0, "Error packing request.");
    } 
    
    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);
    error = vconn_send_block(vconn, ofpbuf);

  
    if (error) {
        ofp_fatal(0, "Error during transaction.");
    }

    dpctl_barrier(vconn);
}

static void
dpctl_send_and_print(struct vconn *vconn, struct ofl_msg_header *msg) {
    char *str;
    str = ofl_msg_to_string(msg, &dpctl_exp);
    printf("\nSENDING:\n%s\n\n", str);
    free(str);
    dpctl_send(vconn, msg);
}

static void
ping(struct vconn *vconn, int argc, char *argv[]) {
    uint16_t payload_size = 0;
    size_t times = 0, i;
    struct ofl_msg_echo *reply;

    struct ofl_msg_echo req =
            {{.type = OFPT_ECHO_REQUEST},
             .data_length = 0,
             .data = NULL};

    if (argc > 0) {
        times = atoi(argv[0]);
    }
    if (times == 0) {
        times = 4;
    }
    if (argc > 1) {
        payload_size = atoi(argv[1]);
    } else {
        payload_size = 1024;
    }
    if (payload_size > UINT16_MAX - sizeof(struct ofp_header)) {
        ofp_fatal(0, "payload must be between 0 and %zu bytes.", UINT16_MAX - sizeof(struct ofp_header));
    }

    req.data_length = payload_size;
    req.data     = xmalloc(payload_size);

    for (i=0; i<times; i++) {
        struct timeval start, end;

        random_bytes(req.data, payload_size);

        gettimeofday(&start, NULL);
        dpctl_transact(vconn, (struct ofl_msg_header *)&req, (struct ofl_msg_header **)&reply);
        gettimeofday(&end, NULL);

        if ((req.data_length != reply->data_length) ||
                     (memcmp(req.data, reply->data, req.data_length) != 0)) {
            ofp_fatal(0, "Reply does not match request.");
        }

        printf("%zu bytes from %s: time=%.1f ms\n",
               (reply->data_length - sizeof(struct ofp_header)),
               vconn_get_name(vconn),
               (1000*(double)(end.tv_sec - start.tv_sec)) + (.001*(end.tv_usec - start.tv_usec)));

    }

    free(req.data);
    ofl_msg_free((struct ofl_msg_header *)reply, &dpctl_exp);
}

static void
monitor(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofpbuf *buf;
    struct ofl_msg_header *msg;
    char *str;
    int error;

    printf("MONITORING %s...\n\n", vconn_get_name(vconn));

    for (;;) {
        if (vconn_recv_block(vconn, &buf) == 0) {

            error = ofl_msg_unpack(buf->data, buf->size, &msg, NULL /*xid_ptr*/, &dpctl_exp);
            if (error) {
                ofp_fatal(0, "Error unpacking reply.");
            }

            /* NOTE: if unpack was successful, message takes over ownership of buffer's
             *       data. Rconn and vconn does not allocate headroom, so the ofpbuf
             *       wrapper can simply be deleted, keeping the data for the message. */
            buf->base = NULL;
            buf->data = NULL;
            ofpbuf_delete(buf);

            str = ofl_msg_to_string(msg, &dpctl_exp);
            printf("\nRECEIVED:\n%s\n\n", str);
            free(str);

            ofl_msg_free(msg, &dpctl_exp);
        }
    }
}

static void
features(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_header req =
            {.type = OFPT_FEATURES_REQUEST};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
get_config(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_header req =
            {.type = OFPT_GET_CONFIG_REQUEST};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_desc(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_stats_request_header req =
            {{.type = OFPT_STATS_REQUEST},
             .type = OFPST_DESC, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_flow(struct vconn *vconn, int argc, char *argv[]) {
    
    
    if (!preferred_flow_format){
        struct ofl_msg_stats_request_flow req =
                {{{.type = OFPT_STATS_REQUEST},
                  .type = OFPST_FLOW, .flags = 0x0000},
                 .cookie = 0x0000000000000000ULL,
                 .cookie_mask = 0x0000000000000000ULL,
                 .table_id = 0xff,
                 .out_port = OFPP_ANY,
                 .out_group = OFPG_ANY,
                 .match = NULL};

        if (argc > 0) {
            parse_flow_stat_args(argv[0], &req);
        }
        if (argc > 1) {
            parse_match(argv[1], &(req.match), preferred_flow_format);
        } else {
            make_all_match(&(req.match));
        }
        dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
    }
    else {
        struct ofl_ext_flow_stats_request request = 
            {{{{ .type = OFPT_STATS_REQUEST},
                 .type = OFPST_EXPERIMENTER, .flags =  0x0000},
                 .experimenter_id = EXTENDED_MATCH_ID},
                 .cookie_mask = 0x0000000000000000ULL,
                 .table_id = 0xff,
                 .out_port = OFPP_ANY,
                 .out_group = OFPG_ANY,
                 .match = NULL};
                 
        if (argc > 0) {
            parse_ext_flow_stat_args(argv[0], &request);
        }
        if (argc > 1) {
            parse_match(argv[1], &(request.match), preferred_flow_format);
        } else {
            make_ext_all_match(&(request.match));
        }
            
            dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&request, NULL);
    }


}

static void
stats_aggr(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_stats_request_flow req =
            {{{.type = OFPT_STATS_REQUEST},
              .type = OFPST_AGGREGATE, .flags = 0x0000},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .match = NULL};

    if (argc > 0) {
        parse_flow_stat_args(argv[0], &req);
    }
    if (argc > 1) {
        parse_match(argv[1], &(req.match), preferred_flow_format);
    } else {
        make_all_match(&(req.match));
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_table(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_stats_request_header req =
            {{.type = OFPT_STATS_REQUEST},
             .type = OFPST_TABLE, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_port(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_stats_request_port req =
            {{{.type = OFPT_STATS_REQUEST},
              .type = OFPST_PORT, .flags = 0x0000},
             .port_no = OFPP_ANY};

    if (argc > 0 && parse_port(argv[0], &req.port_no)) {
        ofp_fatal(0, "Error parsing port: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_queue(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_stats_request_queue req =
            {{{.type = OFPT_STATS_REQUEST},
              .type = OFPST_QUEUE, .flags = 0x0000},
             .port_no = OFPP_ANY,
             .queue_id = OFPQ_ALL};

    if (argc > 0 && parse_port(argv[0], &req.port_no)) {
        ofp_fatal(0, "Error parsing port: %s.", argv[0]);
    }
    if (argc > 1 && parse_queue(argv[1], &req.queue_id)) {
        ofp_fatal(0, "Error parsing queue: %s.", argv[1]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_group(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_stats_request_group req =
            {{{.type = OFPT_STATS_REQUEST},
              .type = OFPST_GROUP, .flags = 0x0000},
             .group_id = OFPG_ALL};

    if (argc > 0 && parse_group(argv[0], &req.group_id)) {
        ofp_fatal(0, "Error parsing group: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_group_desc(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_stats_request_group req =
            {{{.type = OFPT_STATS_REQUEST},
              .type = OFPST_GROUP_DESC, .flags = 0x0000},
             .group_id = OFPG_ALL};

    if (argc > 0 && parse_group(argv[0], &req.group_id)) {
        ofp_fatal(0, "Error parsing group: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}





static void
set_config(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_set_config msg =
            {{.type = OFPT_SET_CONFIG},
             .config = NULL};

    msg.config = xmalloc(sizeof(struct ofl_config));
    msg.config->flags = OFPC_FRAG_NORMAL;
    msg.config->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

    parse_config(argv[0], msg.config);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
do_flow_mod(struct vconn *vconn, int argc, char *argv[]) {
    
   if (!preferred_flow_format){
        struct ofl_msg_flow_mod msg =
            {{.type = OFPT_FLOW_MOD},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .command = OFPFC_ADD,
             .idle_timeout = OFP_FLOW_PERMANENT,
             .hard_timeout = OFP_FLOW_PERMANENT,
             .priority = OFP_DEFAULT_PRIORITY,
             .buffer_id = 0xffffffff,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .flags = 0xffff,
             .match = NULL,
             .instructions_num = 0,
             .instructions = NULL};
              
        parse_flow_mod_args(argv[0], &msg);
       
        if (argc > 1) {
            size_t i;
            size_t inst_num = argc - 2;
            parse_match(argv[1], &(msg.match), preferred_flow_format);
            msg.instructions_num = inst_num;
            msg.instructions = xmalloc(sizeof(struct ofl_instruction_header *) * inst_num);

            for (i=0; i < inst_num; i++) {
                parse_inst(argv[2+i], &(msg.instructions[i]));
            }
        } else {
            make_all_match(&(msg.match));
        }  
         dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
   }
   else /*Extended match flow format */
      if(preferred_flow_format == EXT_MATCH){
        struct ofl_ext_flow_mod msg = 
        {{{  {.type = OFPT_EXPERIMENTER  },
             .experimenter_id = EXTENDED_MATCH_ID},
             .type =  EXT_FLOW_MOD},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .command = OFPFC_ADD,
             .idle_timeout = OFP_FLOW_PERMANENT,
             .hard_timeout = OFP_FLOW_PERMANENT,
             .priority = OFP_DEFAULT_PRIORITY,
             .buffer_id = 0xffffffff,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .flags = 0xffff,
             .match = NULL,
             .instructions_num = 0,
             .instructions = NULL};  
        
        parse_ext_flow_mod_args(argv[0], &msg);
        if (argc > 1){
            size_t i;
            size_t inst_num = argc - 2;
            
            parse_match(argv[1], &(msg.match), preferred_flow_format);
        
            msg.instructions_num = inst_num;
            msg.instructions = xmalloc(sizeof(struct ofl_instruction_header *) * inst_num);

            for (i=0; i < inst_num; i++) {
                parse_inst(argv[2+i], &(msg.instructions[i]));
            }
       }
       
       dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
       
    }
    
}



static void
group_mod(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_group_mod msg =
            {{.type = OFPT_GROUP_MOD},
             .command  = OFPGC_ADD,
             .type     = OFPGT_ALL,
             .group_id = OFPG_ALL,
             .buckets_num = 0,
             .buckets = NULL};

    parse_group_mod_args(argv[0], &msg);

    if (argc > 1) {
        size_t i;
        size_t buckets_num = (argc - 1) / 2;

        msg.buckets_num = buckets_num;
        msg.buckets = xmalloc(sizeof(struct ofl_bucket *) * buckets_num);

        for (i=0; i < buckets_num; i++) {
            msg.buckets[i] = xmalloc(sizeof(struct ofl_bucket));
            msg.buckets[i]->weight = 0;
            msg.buckets[i]->watch_port = OFPP_ANY;
            msg.buckets[i]->watch_group = OFPG_ANY;
            msg.buckets[i]->actions_num = 0;
            msg.buckets[i]->actions = NULL;

            parse_bucket(argv[i*2+1], msg.buckets[i]);
            parse_actions(argv[i*2+2], &(msg.buckets[i]->actions_num), &(msg.buckets[i]->actions));
        }
    }

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
port_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_port_mod msg =
            {{.type = OFPT_PORT_MOD},
             .port_no = OFPP_ANY,
             .config = 0x00000000,
             .mask = 0x00000000,
             .advertise = 0x00000000
            };
            memcpy(msg.hw_addr, mask_all, OFP_ETH_ALEN);

    parse_port_mod(argv[0], &msg);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
table_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_table_mod msg =
            {{.type = OFPT_TABLE_MOD},
             .table_id = 0xff,
             .config = 0x00};

    parse_table_mod(argv[0], &msg);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
queue_get_config(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_queue_get_config_request msg =
            {{.type = OFPT_QUEUE_GET_CONFIG_REQUEST},
             .port = OFPP_ALL};

    if (parse_port(argv[0], &msg.port)) {
        ofp_fatal(0, "Error parsing queue_get_config port: %s.", argv[0]);
    }

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
set_desc(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_exp_openflow_msg_set_dp_desc msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_SET_DESC},
             .dp_desc = argv[0]};

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
queue_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_packet_queue *pq;
    struct ofl_queue_prop_min_rate *p;

    struct ofl_exp_openflow_msg_queue msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_QUEUE_MODIFY},
             .port_id = OFPP_ANY,
             .queue = NULL};

    if (parse_port(argv[0], &msg.port_id)) {
        ofp_fatal(0, "Error parsing queue_mod port: %s.", argv[0]);
    }

    pq = xmalloc(sizeof(struct ofl_packet_queue));
    msg.queue = pq;
    if (parse_queue(argv[1], &pq->queue_id)) {
        ofp_fatal(0, "Error parsing queue_mod queue: %s.", argv[1]);
    }

    pq->properties_num = 1;
    pq->properties = xmalloc(sizeof(struct ofl_queue_prop_header *));

    p = xmalloc(sizeof(struct ofl_queue_prop_min_rate));
    pq->properties[0] = (struct ofl_queue_prop_header *)p;
    p->header.type = OFPQT_MIN_RATE;

    if (parse16(argv[2], NULL,0, UINT16_MAX, &p->rate)) {
        ofp_fatal(0, "Error parsing queue_mod bw: %s.", argv[2]);
    }


    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
queue_del(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_packet_queue *pq;

    struct ofl_exp_openflow_msg_queue msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_QUEUE_DELETE},
             .port_id = OFPP_ANY,
             .queue = NULL};

    if (parse_port(argv[0], &msg.port_id)) {
        ofp_fatal(0, "Error parsing queue_mod port: %s.", argv[0]);
    }

    pq = xmalloc(sizeof(struct ofl_packet_queue));
    msg.queue = pq;
    if (parse_queue(argv[1], &pq->queue_id)) {
        ofp_fatal(0, "Error parsing queue_mod queue: %s.", argv[1]);
    }

    pq->properties_num = 0;
    pq->properties = NULL;

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}

static struct command all_commands[] = {
    {"ping", 0, 2, ping},
    {"monitor", 0, 0, monitor},

    {"features", 0, 0, features },
    {"get-config", 0, 0, get_config},
    {"stats-desc", 0, 0, stats_desc },
    {"stats-flow", 0, 2, stats_flow},
    {"stats-aggr", 0, 2, stats_aggr},
    {"stats-table", 0, 0, stats_table },
    {"stats-port", 0, 1, stats_port },
    {"stats-queue", 0, 2, stats_queue },
    {"stats-group", 0, 1, stats_group },
    {"stats-group-desc", 0, 1, stats_group_desc },

    {"set-config", 1, 1, set_config},
    {"flow-mod", 1, 7/*+1 for each inst type*/, do_flow_mod },
    {"group-mod", 1, UINT8_MAX, group_mod },
    {"port-mod", 1, 1, port_mod },
    {"table-mod", 1, 1, table_mod },
    {"queue-get-config", 1, 1, queue_get_config},

    {"set-desc", 1, 1, set_desc},
    {"queue-mod", 3, 3, queue_mod},
    {"queue-del", 2, 2, queue_del}
};


int main(int argc, char *argv[])
{

    struct command *p;
    struct vconn *vconn;
    size_t i;
    int error;
    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    argc -= optind;
    argv += optind;
   
    if (argc < 1){
        ofp_fatal(0, "missing SWITCH; use --help for help");
             
    }
    if (argc < 2)
        ofp_fatal(0, "missing COMMAND; use --help for help");

    error = vconn_open_block(argv[0], OFP_VERSION, &vconn);
    if (error) {
        ofp_fatal(error, "Error connecting to switch %s.", argv[0]);
    }
    argc -= 1;
    argv += 1;
     
    for (i=0; i<NUM_ELEMS(all_commands); i++) {
        p = &all_commands[i];
        if (strcmp(p->name, argv[0]) == 0) {
            argc -= 1;
            argv += 1;
            if (argc < p->min_args)
                ofp_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            else if (argc > p->max_args)
                ofp_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            else {
               
                p->handler(vconn, argc, argv);
                if (ferror(stdout)) {
                    ofp_fatal(0, "write to stdout failed");
                }
                if (ferror(stderr)) {
                    ofp_fatal(0, "write to stderr failed");
                }
                vconn_close(vconn);
                exit(0);
            }
        }
    }
    ofp_fatal(0, "unknown command '%s'; use --help for help", argv[0]);
    vconn_close(vconn);
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1
    };
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"verbose", optional_argument, 0, 'v'},
        {"flow-format", required_argument, 0, 'F'},
        {"strict", no_argument, 0, OPT_STRICT},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ofp_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;
       case 'F':
            preferred_flow_format = ofputil_flow_format_from_string(optarg);
            if (preferred_flow_format < 0) {
                ofp_fatal(0, "unknown flow format `%s'", optarg);
            }
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        VCONN_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}



static void
usage(void)
{
    printf("%s: OpenFlow switch management utility\n"
           "usage: %s [OPTIONS] SWITCH COMMAND [ARG...]\n"
            "  SWITCH ping [N] [B]                    latency of B-byte echos N times\n"
            "  SWITCH monitor                         monitors packets from the switch\n"
            "\n"
            "  SWITCH features                        show basic information\n"
            "  SWITCH get-config                      get switch configuration\n"
            "  SWITCH stats-desc                      print switch description\n"
            "  SWITCH stats-flow [ARG [MATCH]]        print flow stats\n"
            "  SWITCH stats-aggr [ARG [MATCH]]        print flow aggregate stats\n"
            "  SWITCH stats-table                     print table stats\n"
            "  SWITCH stats-port [PORT]               print port statistics\n"
            "  SWITCH stats-queue [PORT [QUEUE]]      print queue statistics\n"
            "  SWITCH stats-group [GROUP]             print group statistics\n"
            "  SWITCH stats-group-desc [GROUP]        print group desc statistics\n"
            "\n"
            "  SWITCH set-config ARG                  set switch configuration\n"
            "  SWITCH flow-mod ARG [MATCH [INST...]]  send flow_mod message\n"
            "  SWITCH group-mod ARG [BUCARG ACT...]   send group_mod message\n"
            "  SWITCH port-mod ARG                    send port_mod message\n"
            "  SWITCH table-mod ARG                   send table_mod message\n"
            "  SWITCH queue-get-config PORT           send queue_get_config message\n"
            "\n"
            "OpenFlow extensions\n"
            "  SWITCH set-desc DESC                   sets the DP description\n"
            "  SWITCH queue-mod PORT QUEUE BW         adds/modifies queue\n"
            "  SWITCH queue-del PORT QUEUE            deletes queue\n"
            "\n",
            program_name, program_name);
     vconn_usage(true, false, false);
     vlog_usage();
     printf("\nOther options:\n"
            "  --strict                    use strict match for flow commands\n"
            "  -t, --timeout=SECS          give up after SECS seconds\n"
            "  -F, --flow-format=FORMAT    force particular flow format\n"
            "  -h, --help                  display this help message\n"
            "  -V, --version               display version information\n");
     exit(EXIT_SUCCESS);
}

static int
parse_wildcards(char *str, uint32_t *wc) {
    bool add = true;
    bool found;
    size_t i, idx = 0;

    (*wc) = 0x00000000;
    if(!strcmp(str,"none"))
        return 0;

    while (idx < strlen(str)) {
        if (str[idx] == WILDCARD_SUB) {
            add = false;
            idx++;
            continue;
        }
        if (str[idx] == WILDCARD_ADD) {
            add = true;
            idx++;
            continue;
        }
        found = false;
        for (i=0; i<NUM_ELEMS(wildcard_names); i++) {
            if (strncmp(str+idx, wildcard_names[i].name, strlen(wildcard_names[i].name)) == 0) {
                if (add) {
                    (*wc) |= wildcard_names[i].code;
                } else {
                    (*wc) &= ~wildcard_names[i].code;
                }
                add = true;
                idx+=strlen(wildcard_names[i].name);
                found = true;
                break;
            }
        }
        if (!found) {
            return -1;
        }
    }
    return 0;
}


static void
parse_match(char *str, struct ofl_match_header **match, int flow_format) {
    // TODO parse shortcuts: "ip", "arp", "icmp", "tcp", "udp"
    
    /*check for the flow_format */
    char *token, *saveptr = NULL;
    //TODO find a better way to do it
    struct ofl_match_standard *m; 
    struct ofl_ext_match *ext_m;
    uint32_t wildcards;
    
    
    if (!flow_format){
        m = xmalloc(sizeof(struct ofl_match_standard));
        memset(m, 0x00, OFPMT_STANDARD_LENGTH);
        m->header.type = OFPMT_STANDARD;
    }
    else {   
        ext_m = xmalloc(sizeof(struct ofl_ext_match) + 128);     
        ext_m->header.type = EXT_MATCH;
        ext_m->header.length = sizeof(struct ext_match);
        flex_array_init(&(ext_m->match_fields));
        /* Wildcards should be the first field when the flow type is EXT_MATCH */
        token = strtok_r(str, KEY_SEP, &saveptr);
        if (parse_wildcards(token + strlen(MATCH_WILDCARDS KEY_VAL), &(wildcards))) {
            ofp_fatal(0, "Wildcard must be the first match field when using nxm : %s.", token);
        }
        str = NULL;
    }
    
    
    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        /*in_port */
        if (strncmp(token, MATCH_IN_PORT KEY_VAL, strlen(MATCH_IN_PORT KEY_VAL)) == 0) {
            if(!flow_format){
                if (parse_port(token + strlen(MATCH_IN_PORT KEY_VAL), &(m->in_port))) {
                    ofp_fatal(0, "Error parsing port: %s.", token);
                }
            }    
            else {
                uint32_t port;
                parse_port(token + strlen(MATCH_IN_PORT KEY_VAL), &port);
                if( (wildcards & OFPFW_IN_PORT) != 0){
                     ext_put_32w(&ext_m->match_fields, TLV_EXT_IN_PORT_W, port, 0xffffffff);
                     ext_m->header.length += 4;        
                }
                else ext_put_32(&ext_m->match_fields, TLV_EXT_IN_PORT, port);
                ext_m->header.length += 8;
            
            }/*mount the extended entry */    
            continue;
        }
        /*wildcards */
        if (strncmp(token, MATCH_WILDCARDS KEY_VAL, strlen(MATCH_WILDCARDS KEY_VAL)) == 0) {
            if(!flow_format){
                if (parse_wildcards(token + strlen(MATCH_WILDCARDS KEY_VAL), &(m->wildcards))) {
                    ofp_fatal(0, "Error parsing wildcards: %s.", token);
                }
            }
            continue;
        }
        /*DL_SRC*/
        if (strncmp(token, MATCH_DL_SRC KEY_VAL, strlen(MATCH_DL_SRC KEY_VAL)) == 0) {
            if(!flow_format){
                if (parse_dl_addr(token + strlen(MATCH_DL_SRC KEY_VAL), m->dl_src)) {
                    ofp_fatal(0, "Error parsing dl_src: %s.", token);
                }
            }
            else {
                uint8_t dl_src[ETH_ADDR_LEN];
                if (parse_dl_addr(token + strlen(MATCH_DL_SRC KEY_VAL), dl_src)) 
                    ofp_fatal(0, "Error parsing dl_src: %s.", token);
                ext_put_eth(&ext_m->match_fields,TLV_EXT_DL_SRC,dl_src);
                ext_m->header.length += 28;       
            }    
            continue;
        }
        /*dl_src_mask */
        if (strncmp(token, MATCH_DL_SRC_MASK KEY_VAL, strlen(MATCH_DL_SRC_MASK KEY_VAL)) == 0) {
            if(!flow_format){
                if (parse_dl_addr(token + strlen(MATCH_DL_SRC_MASK KEY_VAL), m->dl_src_mask)) {
                    ofp_fatal(0, "Error parsing dl_src_mask: %s.", token);
                }
            }
            else {
                
            
            }    
            continue;
        }
        /*DL_DST */
        if (strncmp(token, MATCH_DL_DST KEY_VAL, strlen(MATCH_DL_DST KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_dl_addr(token + strlen(MATCH_DL_DST KEY_VAL), m->dl_dst)) {
                    ofp_fatal(0, "Error parsing dl_dst: %s.", token);
                }
            }
            else {
                uint8_t dl_dst[ETH_ADDR_LEN];
                if (parse_dl_addr(token + strlen(MATCH_DL_DST KEY_VAL), dl_dst)) 
                    ofp_fatal(0, "Error parsing dl_dst: %s.", token);
                ext_put_eth(&ext_m->match_fields,TLV_EXT_DL_DST,dl_dst);
                ext_m->header.length += 28;       
            
            }    
            continue;
        }
        if (strncmp(token, MATCH_DL_DST_MASK KEY_VAL, strlen(MATCH_DL_DST_MASK KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_dl_addr(token + strlen(MATCH_DL_DST_MASK KEY_VAL), m->dl_dst_mask)) {
                    ofp_fatal(0, "Error parsing dl_dst_mask: %s.", token);
                }
            }
            else {
                
            
            }    
            continue;
        }
        /*dl_vlan */
        if (strncmp(token, MATCH_DL_VLAN KEY_VAL, strlen(MATCH_DL_VLAN KEY_VAL)) == 0) {
            if(!flow_format){
                if (parse_vlan_vid(token + strlen(MATCH_DL_VLAN KEY_VAL), &(m->dl_vlan))) {
                    ofp_fatal(0, "Error parsing vlan label: %s.", token);
                }
            }
            else {
                uint16_t dl_vlan;
                if (parse16(token + strlen(MATCH_DL_VLAN KEY_VAL), NULL, 0, 0xffff, &dl_vlan))
                    ofp_fatal(0, "Error parsing dl_vlan label: %s.", token);
                if( (wildcards & OFPFW_DL_VLAN) != 0){
                    uint16_t mask = 0xffff;
                    ext_put_16w(&ext_m->match_fields, TLV_EXT_DL_VLAN_W, dl_vlan, mask);
                    ext_m->header.length += 2;   
                }
                else 
                    ext_put_16(&ext_m->match_fields, TLV_EXT_DL_VLAN, dl_vlan);
                ext_m->header.length += 6;
            
            }    
            continue;
        }
        /*dl_vlan_pcp */
        if (strncmp(token, MATCH_DL_VLAN_PCP KEY_VAL, strlen(MATCH_DL_VLAN_PCP KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse8(token + strlen(MATCH_DL_VLAN_PCP KEY_VAL), NULL, 0, 0x7, &(m->dl_vlan_pcp))) {
                    ofp_fatal(0, "Error parsing vlan pcp: %s.", token);
                }
            }
            else {
                uint8_t dl_vlan_pcp;
                if (parse8(token + strlen(MATCH_DL_VLAN_PCP KEY_VAL), NULL, 0, 0x3f, &(dl_vlan_pcp))) {
                    ofp_fatal(0, "Error parsing dl_vlan_pcp: %s.", token);
                }
                if( (wildcards & OFPFW_DL_VLAN_PCP) != 0){
                    uint8_t mask = 0xff;
                    ext_put_8w(&ext_m->match_fields, TLV_EXT_DL_VLAN_PCP_W, dl_vlan_pcp, mask);
                    ext_m->header.length += 1;   
                }
                else 
                    ext_put_8(&ext_m->match_fields, TLV_EXT_DL_VLAN_PCP, dl_vlan_pcp);
                ext_m->header.length += 5;  
            
            }
            continue;
        }
        /*dl_type */
        if (strncmp(token, MATCH_DL_TYPE KEY_VAL, strlen(MATCH_DL_TYPE KEY_VAL)) == 0 ) {
            if(!flow_format){
                if (parse16(token + strlen(MATCH_DL_TYPE KEY_VAL), NULL, 0, 0xffff, &(m->dl_type))) {
                    ofp_fatal(0, "Error parsing dl_type: %s.", token);
                }
            }
            else {
                uint16_t dl_type;
                if (parse16(token + strlen(MATCH_DL_TYPE KEY_VAL), NULL, 0, 0xffff, &dl_type))
                    ofp_fatal(0, "Error parsing dl_type: %s.", token);
                if( (wildcards & OFPFW_DL_TYPE) != 0){
                    uint16_t mask = 0xffff;
                    ext_put_16w(&ext_m->match_fields, TLV_EXT_DL_TYPE_W, dl_type, mask);
                    ext_m->header.length += 2;   
                }
                else 
                    ext_put_16(&ext_m->match_fields, TLV_EXT_DL_TYPE, dl_type);
                ext_m->header.length += 6;

            } 
            continue;
        }
        /* NW_TOS */
        if (strncmp(token, MATCH_NW_TOS KEY_VAL, strlen(MATCH_NW_TOS KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse8(token + strlen(MATCH_NW_TOS KEY_VAL), NULL, 0, 0x3f, &(m->nw_tos))) {
                    ofp_fatal(0, "Error parsing nw_tos: %s.", token);
                }
            }
            else {
                uint8_t nw_tos;
                if (parse8(token + strlen(MATCH_NW_TOS KEY_VAL), NULL, 0, 0x3f, &(nw_tos))) {
                    ofp_fatal(0, "Error parsing nw_tos: %s.", token);
                }
                if( (wildcards & OFPFW_NW_TOS) != 0){
                    uint8_t mask = 0xff;
                    ext_put_8w(&ext_m->match_fields, TLV_EXT_NW_TOS_W, nw_tos, mask);
                    ext_m->header.length += 1;   
                }
                else 
                    ext_put_8(&ext_m->match_fields, TLV_EXT_NW_TOS, nw_tos);
                ext_m->header.length += 5;
            }
            continue;
        }
        /*NW_PROTO */
        if (strncmp(token, MATCH_NW_PROTO KEY_VAL, strlen(MATCH_NW_PROTO KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse8(token + strlen(MATCH_NW_PROTO KEY_VAL), NULL, 0, 0xff, &(m->nw_proto))) {
                    ofp_fatal(0, "Error parsing nw_proto: %s.", token);
                }
            }
            else {
                uint8_t nw_tos;
                if (parse8(token + strlen(MATCH_NW_PROTO KEY_VAL), NULL, 0, 0xff, &(nw_tos))) {
                    ofp_fatal(0, "Error parsing nw_proto: %s.", token);
                }
                if( (wildcards & OFPFW_NW_PROTO) != 0){
                    uint8_t mask = 0xff;
                    ext_put_8w(&ext_m->match_fields, TLV_EXT_NW_PROTO_W, nw_tos, mask);
                    ext_m->header.length += 1;   
                }
                else 
                    ext_put_8(&ext_m->match_fields, TLV_EXT_NW_PROTO, nw_tos);
                ext_m->header.length += 5;
            }
            continue;
        }
        /*NW_SRC */
        if (strncmp(token, MATCH_NW_SRC KEY_VAL, strlen(MATCH_NW_SRC KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_nw_addr(token + strlen(MATCH_NW_SRC KEY_VAL), &(m->nw_src))) {
                    ofp_fatal(0, "Error parsing nw_src: %s.", token);
                }
            }
            else {
                uint32_t nw_src;
                if (parse_nw_addr(token + strlen(MATCH_NW_SRC KEY_VAL), &(nw_src))) {
                    ofp_fatal(0, "Error parsing nw_src: %s.", token);
                }
                /*if( (wildcards & OFPFW_IN_PORT) != 0){
                     ext_put_32w(&ext_m->match_fields, TLV_EXT_IN_PORT_W, port, 0x00);
                     ext_m->header.length += 4;        
                }*/
                ext_put_32(&ext_m->match_fields, TLV_EXT_IP_SRC, nw_src);
                ext_m->header.length += 8;
            
            }
            continue;
        }
        if (strncmp(token, MATCH_NW_SRC_MASK KEY_VAL, strlen(MATCH_NW_SRC_MASK KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_nw_addr(token + strlen(MATCH_NW_SRC_MASK KEY_VAL), &(m->nw_src_mask))) {
                    ofp_fatal(0, "Error parsing nw_src_mask: %s.", token);
                }
            }
            else {
            
            
            }
            continue;
        }
        /*NW_DST */
        if (strncmp(token, MATCH_NW_DST KEY_VAL, strlen(MATCH_NW_DST KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_nw_addr(token + strlen(MATCH_NW_DST KEY_VAL), &(m->nw_dst))) {
                    ofp_fatal(0, "Error parsing nw_dst: %s.", token);
                }
            }
            else {
                uint32_t nw_dst;
                if (parse_nw_addr(token + strlen(MATCH_NW_DST KEY_VAL), &(nw_dst))) {
                    ofp_fatal(0, "Error parsing nw_src: %s.", token);
                }
                /*if( (wildcards & OFPFW_IN_PORT) != 0){
                     ext_put_32w(&ext_m->match_fields, TLV_EXT_IN_PORT_W, port, 0x00);
                     ext_m->header.length += 4;        
                }*/
                ext_put_32(&ext_m->match_fields, TLV_EXT_IP_DST, nw_dst);
                ext_m->header.length += 8;
            
            }
            continue;
        }
        if (strncmp(token, MATCH_NW_DST_MASK KEY_VAL, strlen(MATCH_NW_DST_MASK KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse_nw_addr(token + strlen(MATCH_NW_DST_MASK KEY_VAL), &(m->nw_dst_mask))) {
                    ofp_fatal(0, "Error parsing nw_dst_mask: %s.", token);
                }
            }
            else {
            
            
            }
            continue;
        }
        /*TP_SRC */
        if (strncmp(token, MATCH_TP_SRC KEY_VAL, strlen(MATCH_TP_SRC KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse16(token + strlen(MATCH_TP_SRC KEY_VAL), NULL, 0, 0xffff, &(m->tp_src))) {
                    ofp_fatal(0, "Error parsing tp_src: %s.", token);
                }
            }
            else {
                uint16_t tp_src;
                if (parse16(token + strlen(MATCH_TP_SRC KEY_VAL), NULL, 0, 0xffff, &tp_src))
                    ofp_fatal(0, "Error parsing dl_type: %s.", token);
                if( (wildcards & OFPFW_TP_SRC) != 0){
                    uint16_t mask = 0xffff;
                    ext_put_16w(&ext_m->match_fields, TLV_EXT_TP_SRC_W, tp_src, mask);
                    ext_m->header.length += 2;   
                }
                else 
                    ext_put_16(&ext_m->match_fields, TLV_EXT_TP_SRC, tp_src);
                ext_m->header.length += 6;
            
            }
            continue;
        }
        /*TP_DST */
        if (strncmp(token, MATCH_TP_DST KEY_VAL, strlen(MATCH_TP_DST KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse16(token + strlen(MATCH_TP_DST KEY_VAL), NULL, 0, 0xffff, &(m->tp_dst))) {
                    ofp_fatal(0, "Error parsing tp_dst: %s.", token);
                }
            }
            else {
                uint16_t tp_dst;
                if (parse16(token + strlen(MATCH_TP_DST KEY_VAL), NULL, 0, 0xffff, &tp_dst))
                    ofp_fatal(0, "Error parsing dl_type: %s.", token);
                if( (wildcards & OFPFW_TP_DST) != 0){
                    uint16_t mask = 0xffff;
                    ext_put_16w(&ext_m->match_fields, TLV_EXT_TP_DST_W, tp_dst, mask);
                    ext_m->header.length += 2;   
                }
                else 
                    ext_put_16(&ext_m->match_fields, TLV_EXT_TP_DST, tp_dst);
                ext_m->header.length += 6;
            }
            continue;
        }
        /*MPLS_LABEL */
        if (strncmp(token, MATCH_MPLS_LABEL KEY_VAL, strlen(MATCH_MPLS_LABEL KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse32(token + strlen(MATCH_MPLS_LABEL KEY_VAL), NULL, 0, 0xfffff, &(m->mpls_label))) {
                    ofp_fatal(0, "Error parsing mpls_label: %s.", token);
                }
            }
            else {
                uint32_t mpls_label;
                parse_port(token + strlen(MATCH_MPLS_LABEL KEY_VAL), &mpls_label);
                if( (wildcards & OFPFW_MPLS_LABEL) != 0){
                     ext_put_32w(&ext_m->match_fields, TLV_EXT_MPLS_LABEL_W, mpls_label, 0x00000000);
                     ext_m->header.length += 4;        
                }
                else ext_put_32(&ext_m->match_fields, TLV_EXT_MPLS_LABEL,mpls_label);
                ext_m->header.length += 8;
            }
            continue;
        }
        /* MPLS_TC */
        if (strncmp(token, MATCH_MPLS_TC KEY_VAL, strlen(MATCH_MPLS_TC KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (parse8(token + strlen(MATCH_MPLS_TC KEY_VAL), NULL, 0, 0x07, &(m->mpls_tc))) {
                    ofp_fatal(0, "Error parsing mpls_tc: %s.", token);
                }
            }
            else {
                uint8_t mpls_tc;
                if (parse8(token + strlen(MATCH_MPLS_TC KEY_VAL), NULL, 0, 0x3f, &(mpls_tc))) {
                    ofp_fatal(0, "Error parsing nw_tos: %s.", token);
                }
                if( (wildcards & OFPFW_NW_TOS) != 0){
                    uint8_t mask = 0xff;
                    ext_put_8w(&ext_m->match_fields, TLV_EXT_MPLS_TC_W, mpls_tc, mask);
                    ext_m->header.length += 1;   
                }
                else 
                    ext_put_8(&ext_m->match_fields, TLV_EXT_MPLS_TC, mpls_tc);
                ext_m->header.length += 5;
            
            }
            continue;
        }
        if (strncmp(token, MATCH_NW_SRC_IPV6 , strlen(MATCH_NW_SRC_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 struct in6_addr addr, mask;
                 if (str_to_ipv6(token + strlen(MATCH_NW_SRC_IPV6)+1, &addr, &mask) < 0) {
                     ofp_fatal(0, "Error parsing nw_src_ipv6: %s.", token);
                 }
                 else 
                    ext_put_ipv6(&ext_m->match_fields,TLV_EXT_IPV6_SRC_W, &addr, &mask);
                    
                 ext_m->header.length += 36; 
            }
            continue;
        }
        /* IPv6 dst address */
        if (strncmp(token, MATCH_NW_DST_IPV6 , strlen(MATCH_NW_DST_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 struct in6_addr addr, mask;
                 if (str_to_ipv6(token + strlen(MATCH_NW_DST_IPV6)+1, &addr, &mask) < 0) {
                     ofp_fatal(0, "Error parsing nw_src_ipv6: %s.", token);
                 }
                 else {
                    
                    ext_put_ipv6(&ext_m->match_fields,TLV_EXT_IPV6_DST_W, &addr, &mask);
                    
                    }
                 ext_m->header.length += 36; 
            }
            continue;
        }
        /*Routing extension header */
        if (strncmp(token, MATCH_ROUTING_HEADER_IPV6 , strlen(MATCH_ROUTING_HEADER_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t rh_type = 43;
                 ext_put_8(&ext_m->match_fields, TLV_EXT_IPV6_RH_ID , rh_type /*Routing Next Header Value */);
                 ext_m->header.length += 5;
            }
            continue;
        }
	    /*Routing extension header Addresses */
        if (strncmp(token, MATCH_ROUTING_ADDRESS_IPV6 , strlen(MATCH_ROUTING_ADDRESS_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 struct in6_addr addr, mask;
                 if (str_to_ipv6(token + strlen(MATCH_ROUTING_ADDRESS_IPV6)+1, &addr, &mask) < 0) {
                     ofp_fatal(0, "Error parsing rh_add_ipv6: %s.", token);
                 }
                 else {
                    
                    ext_put_ipv6(&ext_m->match_fields,TLV_EXT_IPV6_RH_ADDRESS, &addr, &mask);
                    
                    }
                 ext_m->header.length += 36; 

            }
            continue;
        }

        /*Hop by Hop header*/
        if (strncmp(token, MATCH_HBH_HEADER_IPV6 , strlen(MATCH_HBH_HEADER_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t v = 0;
                 //uint8_t mask = 0xff;
                 ext_put_8(&ext_m->match_fields, TLV_EXT_IPV6_HBH_ID, v /*Hop by Hop Header Value */);
                 ext_m->header.length += 5;

            }
            continue;
        }
	    /*Hop by Hop Code*/
        if (strncmp(token, MATCH_HBH_OPTION_CODE_IPV6 , strlen(MATCH_HBH_OPTION_CODE_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t hbh_code;
                 uint8_t mask = 0xff;
	         if (parse8(token + strlen(MATCH_HBH_OPTION_CODE_IPV6 KEY_VAL), NULL, 0, 0xff, &(hbh_code))) {
                    ofp_fatal(0, "Error parsing hbh_code: %s.", token);
                 }
                 ext_put_8w(&ext_m->match_fields, TLV_EXT_IPV6_HBH_OPT_CODE, hbh_code /*Hop by Hop Header Value */, mask);
                 ext_m->header.length += 6;

            }
            continue;
        }
	    /*Destination Option Header */
	    if (strncmp(token, MATCH_DO_HEADER_IPV6 , strlen(MATCH_DO_HEADER_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t v = 60;
                 uint8_t mask = 0xff;
                 ext_put_8w(&ext_m->match_fields, TLV_EXT_IPV6_DOH_ID_W, v /*Destination Option Header Value */, mask);
                 ext_m->header.length += 6;

            }
            continue;
        }
	    /*Authentication Header */
	    if (strncmp(token, MATCH_AUTHENTICATION_HEADER_IPV6 , strlen(MATCH_AUTHENTICATION_HEADER_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t v = 51;
                 uint8_t mask = 0xff;
                 ext_put_8w(&ext_m->match_fields, TLV_EXT_IPV6_AH_ID_W, v /*Authentication Header Value */, mask);
                 ext_m->header.length += 6;

            }
            continue;
        }
	    /*Fragmentation Header */
	    if (strncmp(token, MATCH_FRAGMENT_HEADER_IPV6 , strlen(MATCH_FRAGMENT_HEADER_IPV6 )) == 0) {
            if(!flow_format){ 
                   ofp_fatal(0, "IPv6 support need the -F nxm option: %s.", token);
            }
            else {
                 uint8_t v = 44;
                 uint8_t mask = 0xff;
                 ext_put_8w(&ext_m->match_fields, TLV_EXT_IPV6_FH_ID, v /*Fragmentation Header Value */, mask);
                 ext_m->header.length += 6;

            }
            continue;
        }

        if (strncmp(token, MATCH_METADATA_MASK KEY_VAL, strlen(MATCH_METADATA_MASK KEY_VAL)) == 0) {
            if(!flow_format){ 
                if (sscanf(token, MATCH_METADATA_MASK KEY_VAL "0x%"SCNx64"", &(m->metadata_mask)) != 1) {
                    ofp_fatal(0, "Error parsing %s: %s.", MATCH_METADATA_MASK, token);
                }
            }
            else {
            
            
            }
            continue;
        }
        ofp_fatal(0, "Error parsing match arg: %s.", token);
    }
    if (!preferred_flow_format){
        (*match) = (struct ofl_match_header *)m;
    }
    else {
        (*match) = (struct ofl_match_header *)ext_m;  
    }
}   


static void
make_all_match(struct ofl_match_header **match) {
    struct ofl_match_standard *m = xmalloc(sizeof(struct ofl_match_standard));
    memset(m, 0x00, OFPMT_STANDARD_LENGTH);

    m->header.type = OFPMT_STANDARD;
    m->wildcards = OFPFW_ALL;
    memcpy(m->dl_src_mask, mask_all, OFP_ETH_ALEN);
    memcpy(m->dl_dst_mask, mask_all, OFP_ETH_ALEN);
    m->nw_src_mask = 0xffffffff;
    m->nw_dst_mask = 0xffffffff;
    m->metadata_mask = 0xffffffffffffffffULL;

    (*match) = (struct ofl_match_header *)m;
}

static void
make_ext_all_match(struct ofl_match_header **match) {
    struct ofl_ext_match *m = xmalloc(sizeof(struct ofl_ext_match));

    m->header.type = EXT_MATCH;
    m->header.length = sizeof(struct ext_match);
    flex_array_init(&(m->match_fields));

    (*match) = (struct ofl_match_header *)m;
}


static void
parse_action(uint16_t type, char *str, struct ofl_action_header **act) {
    switch (type) {
        case (OFPAT_OUTPUT): {
            char *token, *saveptr = NULL;
            struct ofl_action_output *a = xmalloc(sizeof(struct ofl_action_output));

            token = strtok_r(str, KEY_VAL2, &saveptr);
            if (parse_port(token, &(a->port))) {
                ofp_fatal(0, "Error parsing port in output action: %s.", str);
            }
            token = strtok_r(NULL, KEY_VAL2, &saveptr);
            if (token == NULL) {
                a->max_len = 0;
            } else {
                if (parse16(token, NULL, 0, 0xffff - sizeof(struct ofp_header), &(a->max_len))) {
                    ofp_fatal(0, "Error parsing max_len in output action: %s.", str);
                }
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_VLAN_VID): {
            struct ofl_action_vlan_vid *a = xmalloc(sizeof(struct ofl_action_vlan_vid));
            if (parse_vlan_vid(str, &(a->vlan_vid))) {
                ofp_fatal(0, "Error parsing vid in vlan vid action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_VLAN_PCP): {
            struct ofl_action_vlan_pcp *a = xmalloc(sizeof(struct ofl_action_vlan_pcp));
            if (parse8(str, NULL, 0, 7, &(a->vlan_pcp))) {
                ofp_fatal(0, "Error parsing pcp in vlan pcp action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_DL_SRC):
        case (OFPAT_SET_DL_DST): {
            struct ofl_action_dl_addr *a = xmalloc(sizeof(struct ofl_action_dl_addr));
            if (parse_dl_addr(str, a->dl_addr)) {
                ofp_fatal(0, "Error parsing addr in dl src/dst action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_NW_SRC):
        case (OFPAT_SET_NW_DST): {
            struct ofl_action_nw_addr *a = xmalloc(sizeof(struct ofl_action_nw_addr));
            if (parse_nw_addr(str, &(a->nw_addr))) {
                ofp_fatal(0, "Error parsing addr in nw src/dst action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_NW_TOS): {
            struct ofl_action_nw_tos *a = xmalloc(sizeof(struct ofl_action_nw_tos));
            if (parse8(str, NULL, 0, 0x3f, &(a->nw_tos))) {
                ofp_fatal(0, "Error parsing tos in nw_tos action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_NW_ECN): {
            struct ofl_action_nw_ecn *a = xmalloc(sizeof(struct ofl_action_nw_ecn));
            if (parse8(str, NULL, 0, 3, &(a->nw_ecn))) {
                ofp_fatal(0, "Error parsing ecn in nw_ecn action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_TP_SRC):
        case (OFPAT_SET_TP_DST): {
            struct ofl_action_tp_port *a = xmalloc(sizeof(struct ofl_action_tp_port));
            if (parse16(str, NULL, 0, 0xffff, &(a->tp_port))) {
                ofp_fatal(0, "Error parsing port in tp_src/dst action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_COPY_TTL_OUT):
        case (OFPAT_COPY_TTL_IN): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_SET_MPLS_LABEL): {
            struct ofl_action_mpls_label *a = xmalloc(sizeof(struct ofl_action_mpls_label));
            if (parse32(str, NULL, 0, 0xfffff, &(a->mpls_label))) {
                ofp_fatal(0, "Error parsing label in mpls_label action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_MPLS_TC): {
            struct ofl_action_mpls_tc *a = xmalloc(sizeof(struct ofl_action_mpls_tc));
            if (parse8(str, NULL, 0, 7, &(a->mpls_tc))) {
                ofp_fatal(0, "Error parsing tc in mpls_tc action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            struct ofl_action_mpls_ttl *a = xmalloc(sizeof(struct ofl_action_mpls_ttl));
            if (parse8(str, NULL, 0, 255, &(a->mpls_ttl))) {
                ofp_fatal(0, "Error parsing ttl in mpls_ttl action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_PUSH_VLAN):
        case (OFPAT_PUSH_MPLS): {
            struct ofl_action_push *a = xmalloc(sizeof(struct ofl_action_push));
            if (sscanf(str, "0x%"SCNx16"", &(a->ethertype)) != 1) {
                ofp_fatal(0, "Error parsing ethertype in push_mpls/vlan action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_POP_VLAN): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_POP_MPLS): {
            struct ofl_action_pop_mpls *a = xmalloc(sizeof(struct ofl_action_pop_mpls));
            if (sscanf(str, "0x%"SCNx16"", &(a->ethertype)) != 1) {
                ofp_fatal(0, "Error parsing ethertype in pop_mpls action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_QUEUE): {
            struct ofl_action_set_queue *a = xmalloc(sizeof(struct ofl_action_set_queue));
            if (parse32(str, NULL, 0, 0xffffffff, &(a->queue_id))) {
                ofp_fatal(0, "Error parsing queue in queue action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_GROUP): {
            struct ofl_action_group *a = xmalloc(sizeof(struct ofl_action_group));
            if (parse_group(str, &(a->group_id))) {
                ofp_fatal(0, "Error parsing group in group action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_NW_TTL): {
            struct ofl_action_set_nw_ttl *a = xmalloc(sizeof(struct ofl_action_set_nw_ttl));
            if (parse8(str, NULL, 0, 255, &(a->nw_ttl))) {
                ofp_fatal(0, "Error parsing ttl in mpls_ttl action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        default: {
            ofp_fatal(0, "Error parsing action: %s.", str);
        }
    }
    (*act)->type = type;
}

static void
parse_actions(char *str, size_t *acts_num, struct ofl_action_header ***acts) {
    char *token, *saveptr = NULL;
    char *s;
    size_t i;
    bool found;
    struct ofl_action_header *act = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        found = false;
        for (i=0; i<NUM_ELEMS(action_names); i++) {
            if (strncmp(token, action_names[i].name, strlen(action_names[i].name)) == 0) {
                s = token + strlen(action_names[i].name);

                if (strncmp(s, KEY_VAL, strlen(KEY_VAL)) == 0) {
                    s+= strlen(KEY_VAL);
                }
                parse_action(action_names[i].code, s, &act);
                (*acts_num)++;
                (*acts) = xrealloc((*acts), sizeof(struct ofl_action_header *) * (*acts_num));
                (*acts)[(*acts_num)-1] = act;
                found = true;
                break;
            }
        }
        if (!found) {
            ofp_fatal(0, "Error parsing action: %s.", token);
        }
    }

}

static void
parse_inst(char *str, struct ofl_instruction_header **inst) {
    size_t i;
    char *s;

    for (i=0; i<NUM_ELEMS(inst_names); i++) {
        if (strncmp(str, inst_names[i].name, strlen(inst_names[i].name)) == 0) {

            s = str + strlen(inst_names[i].name);

            if (strncmp(s, KEY_VAL2, strlen(KEY_VAL2)) != 0) {
                ofp_fatal(0, "Error parsing instruction: %s.", str);
            }
            s+= strlen(KEY_VAL2);
            switch (inst_names[i].code) {
                case (OFPIT_GOTO_TABLE): {
                    struct ofl_instruction_goto_table *i = xmalloc(sizeof(struct ofl_instruction_goto_table));
                    i->header.type = OFPIT_GOTO_TABLE;
                    if (parse_table(s, &(i->table_id))) {
                        ofp_fatal(0, "Error parsing table in goto instruction: %s.", s);
                    }
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_WRITE_METADATA): {
                    char *token, *saveptr = NULL;
                    struct ofl_instruction_write_metadata *i = xmalloc(sizeof(struct ofl_instruction_write_metadata));
                    i->header.type = OFPIT_WRITE_METADATA;
                    token = strtok_r(s, KEY_SEP, &saveptr);
                    if (sscanf(token, "0x%"SCNx64"", &(i->metadata)) != 1) {
                        ofp_fatal(0, "Error parsing metadata in write metadata instruction: %s.", s);
                    }
                    token = strtok_r(NULL, KEY_SEP, &saveptr);
                    if (token == NULL) {
                        i->metadata_mask = 0xffffffffffffffffULL;
                    } else {
                        if (sscanf(token, "0x%"SCNx64"", &(i->metadata_mask)) != 1) {
                            ofp_fatal(0, "Error parsing metadata_mask in write metadata instruction: %s.", s);
                        }
                    }
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_WRITE_ACTIONS): {
                    struct ofl_instruction_actions *i = xmalloc(sizeof(struct ofl_instruction_actions));
                    i->header.type = OFPIT_WRITE_ACTIONS;
                    i->actions = NULL;
                    i->actions_num = 0;
                    parse_actions(s, &(i->actions_num), &(i->actions));
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_APPLY_ACTIONS): {
                    struct ofl_instruction_actions *i = xmalloc(sizeof(struct ofl_instruction_actions));
                    i->header.type = OFPIT_APPLY_ACTIONS;
                    i->actions = NULL;
                    i->actions_num = 0;
                    parse_actions(s, &(i->actions_num), &(i->actions));
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_CLEAR_ACTIONS): {
                    struct ofl_instruction_header *i = xmalloc(sizeof(struct ofl_instruction_header));
                    i->type = OFPIT_CLEAR_ACTIONS;
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
            }
        }
    }
    ofp_fatal(0, "Error parsing instruction: %s.", str);
}

static void
parse_ext_flow_stat_args(char *str, struct ofl_ext_flow_stats_request *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_stat table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_stat port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_stat group: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_stat arg: %s.", token);
    }
}

static void
parse_flow_stat_args(char *str, struct ofl_msg_stats_request_flow *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_stat table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_stat port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_stat group: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_stat arg: %s.", token);
    }
}

static void parse_ext_flow_mod_args(char *str,  struct ofl_ext_flow_mod *req) {

    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COMMAND KEY_VAL, strlen(FLOW_MOD_COMMAND KEY_VAL)) == 0) {
            uint8_t command;
            if (parse8(token + strlen(FLOW_MOD_COMMAND KEY_VAL), flow_mod_cmd_names, NUM_ELEMS(flow_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing flow_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_mod table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_IDLE KEY_VAL, strlen(FLOW_MOD_IDLE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_IDLE KEY_VAL "%"SCNu16"", &(req->idle_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_IDLE, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_HARD KEY_VAL, strlen(FLOW_MOD_HARD KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_HARD KEY_VAL "%"SCNu16"", &(req->hard_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_HARD, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_PRIO KEY_VAL, strlen(FLOW_MOD_PRIO KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_PRIO KEY_VAL "%"SCNu16"", &(req->priority)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_PRIO, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_BUFFER KEY_VAL, strlen(FLOW_MOD_BUFFER KEY_VAL)) == 0) {
            if (parse32(token + strlen(FLOW_MOD_BUFFER KEY_VAL), buffer_names, NUM_ELEMS(buffer_names), UINT32_MAX,  &req->buffer_id)) {
                ofp_fatal(0, "Error parsing flow_mod buffer: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod group: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_FLAGS KEY_VAL, strlen(FLOW_MOD_FLAGS KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_FLAGS KEY_VAL "0x%"SCNx16"", &(req->flags)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_FLAGS, token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_mod arg: %s.", token);
    }


}

static void
parse_flow_mod_args(char *str,  struct ofl_msg_flow_mod *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COMMAND KEY_VAL, strlen(FLOW_MOD_COMMAND KEY_VAL)) == 0) {
            uint8_t command;
            if (parse8(token + strlen(FLOW_MOD_COMMAND KEY_VAL), flow_mod_cmd_names, NUM_ELEMS(flow_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing flow_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_mod table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_IDLE KEY_VAL, strlen(FLOW_MOD_IDLE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_IDLE KEY_VAL "%"SCNu16"", &(req->idle_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_IDLE, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_HARD KEY_VAL, strlen(FLOW_MOD_HARD KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_HARD KEY_VAL "%"SCNu16"", &(req->idle_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_HARD, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_PRIO KEY_VAL, strlen(FLOW_MOD_PRIO KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_PRIO KEY_VAL "%"SCNu16"", &(req->idle_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_PRIO, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_BUFFER KEY_VAL, strlen(FLOW_MOD_BUFFER KEY_VAL)) == 0) {
            if (parse32(token + strlen(FLOW_MOD_BUFFER KEY_VAL), buffer_names, NUM_ELEMS(buffer_names), UINT32_MAX,  &req->buffer_id)) {
                ofp_fatal(0, "Error parsing flow_mod buffer: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod group: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_FLAGS KEY_VAL, strlen(FLOW_MOD_FLAGS KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_FLAGS KEY_VAL "0x%"SCNx16"", &(req->flags)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_FLAGS, token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_mod arg: %s.", token);
    }
}

static void
parse_group_mod_args(char *str, struct ofl_msg_group_mod *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, GROUP_MOD_COMMAND KEY_VAL, strlen(GROUP_MOD_COMMAND KEY_VAL)) == 0) {
            uint16_t command;
            if (parse16(token + strlen(GROUP_MOD_COMMAND KEY_VAL), group_mod_cmd_names, NUM_ELEMS(group_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing group_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, GROUP_MOD_GROUP KEY_VAL, strlen(GROUP_MOD_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(GROUP_MOD_GROUP KEY_VAL), &req->group_id)) {
                ofp_fatal(0, "Error parsing group_mod group: %s.", token);
            }
            continue;
        }
        if (strncmp(token, GROUP_MOD_TYPE KEY_VAL, strlen(GROUP_MOD_TYPE KEY_VAL)) == 0) {
            uint8_t type;
            if (parse8(token + strlen(GROUP_MOD_TYPE KEY_VAL), group_type_names, NUM_ELEMS(group_type_names), UINT8_MAX,  &type)) {
                ofp_fatal(0, "Error parsing group_mod type: %s.", token);
            }
            req->type = type;
            continue;
        }
        ofp_fatal(0, "Error parsing group_mod arg: %s.", token);
    }
}

static void
parse_bucket(char *str, struct ofl_bucket *b) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, BUCKET_WEIGHT KEY_VAL, strlen(BUCKET_WEIGHT KEY_VAL)) == 0) {
            if (parse16(token + strlen(BUCKET_WEIGHT KEY_VAL), NULL, 0, UINT16_MAX, &b->weight)) {
                ofp_fatal(0, "Error parsing bucket_weight: %s.", token);
            }
            continue;
        }
        if (strncmp(token, BUCKET_WATCH_PORT KEY_VAL, strlen(BUCKET_WATCH_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(BUCKET_WATCH_PORT KEY_VAL), &b->watch_port)) {
                ofp_fatal(0, "Error parsing bucket watch port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, BUCKET_WATCH_GROUP KEY_VAL, strlen(BUCKET_WATCH_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(BUCKET_WATCH_GROUP KEY_VAL), &b->watch_group)) {
                ofp_fatal(0, "Error parsing bucket watch group: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing bucket arg: %s.", token);
    }
}

static void
parse_config(char *str, struct ofl_config *c) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, CONFIG_FLAGS KEY_VAL, strlen(CONFIG_FLAGS KEY_VAL)) == 0) {
            if (sscanf(token + strlen(CONFIG_FLAGS KEY_VAL), "0x%"SCNx16"", &c->flags) != 1) {
                ofp_fatal(0, "Error parsing config flags: %s.", token);
            }
            continue;
        }
        if (strncmp(token, CONFIG_MISS KEY_VAL, strlen(CONFIG_MISS KEY_VAL)) == 0) {
            if (parse16(token + strlen(CONFIG_MISS KEY_VAL), NULL, 0, UINT16_MAX - sizeof(struct ofp_packet_in), &c->miss_send_len)) {
                ofp_fatal(0, "Error parsing config miss send len: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing config arg: %s.", token);
    }
}

static void
parse_port_mod(char *str, struct ofl_msg_port_mod *msg) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, PORT_MOD_PORT KEY_VAL, strlen(PORT_MOD_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(PORT_MOD_PORT KEY_VAL), &msg->port_no)) {
                ofp_fatal(0, "Error parsing port_mod port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_HW_ADDR KEY_VAL, strlen(PORT_MOD_HW_ADDR KEY_VAL)) == 0) {
            if (parse_dl_addr(token + strlen(PORT_MOD_HW_ADDR KEY_VAL), msg->hw_addr)) {
                ofp_fatal(0, "Error parsing port_mod hw_addr: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_HW_CONFIG KEY_VAL, strlen(PORT_MOD_HW_CONFIG KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_HW_CONFIG KEY_VAL), "0x%"SCNx32"", &msg->config) != 1) {
                ofp_fatal(0, "Error parsing port_mod conf: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_MASK KEY_VAL, strlen(PORT_MOD_MASK KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_MASK KEY_VAL), "0x%"SCNx32"", &msg->mask) != 1) {
                ofp_fatal(0, "Error parsing port_mod mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_ADVERTISE KEY_VAL, strlen(PORT_MOD_ADVERTISE KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_ADVERTISE KEY_VAL), "0x%"SCNx32"", &msg->advertise) != 1) {
                ofp_fatal(0, "Error parsing port_mod advertise: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing port_mod arg: %s.", token);
    }
}


static void
parse_table_mod(char *str, struct ofl_msg_table_mod *msg) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, TABLE_MOD_TABLE KEY_VAL, strlen(TABLE_MOD_TABLE KEY_VAL)) == 0) {
            if (parse_table(token + strlen(TABLE_MOD_TABLE KEY_VAL), &msg->table_id)) {
                ofp_fatal(0, "Error parsing table_mod table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, TABLE_MOD_CONFIG KEY_VAL, strlen(TABLE_MOD_CONFIG KEY_VAL)) == 0) {
            if (sscanf(token + strlen(TABLE_MOD_CONFIG KEY_VAL), "0x%"SCNx32"", &msg->config) != 1) {
                ofp_fatal(0, "Error parsing table_mod conf: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing table_mod arg: %s.", token);
    }
}


static int
parse_port(char *str, uint32_t *port) {
    return parse32(str, port_names, NUM_ELEMS(port_names), OFPP_MAX, port);
}


static int
parse_queue(char *str, uint32_t *port) {
    return parse32(str, queue_names, NUM_ELEMS(queue_names), 0xfffffffe, port);
}

static int
parse_group(char *str, uint32_t *group) {
    return parse32(str, group_names, NUM_ELEMS(group_names), OFPG_MAX, group);
}

static int
parse_table(char *str, uint8_t *table) {
    return parse8(str, table_names, NUM_ELEMS(table_names), 0xfe, table);
}

static int
parse_dl_addr(char *str, uint8_t *addr) {
    return (sscanf(str, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            addr, addr+1, addr+2, addr+3, addr+4, addr+5) != 6);
}

static int
parse_nw_addr(char *str, uint32_t *addr) {
    // TODO Zoltan: netmask ?
    // TODO Zoltan: DNS lookup ?
    uint8_t a[4];

    if (sscanf(str, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
               &a[0], &a[1], &a[2], &a[3]) == 4) {
            *addr = (a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
        return 0;
    }
    return -1;
}

static int
parse_vlan_vid(char *str, uint16_t *vid) {
    return parse16(str, vlan_vid_names, NUM_ELEMS(vlan_vid_names), 0xfff, vid);
}



static int
parse8(char *str, struct names8 *names, size_t names_num, uint8_t max, uint8_t *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }

    if ((max > 0) && (sscanf(str, "%"SCNu8"", val)) == 1 && (*val <= max)) {
        return 0;
    }
    return -1;
}

static int
parse16(char *str, struct names16 *names, size_t names_num, uint16_t max, uint16_t *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }
    
    /* Checks if the passed value is hexadecimal. */
    if(str[1] == 'x'){
        if ((max > 0) && (sscanf(str, "%"SCNx16"", val))  == 1 && (*val <= max)) {
            return 0;
        }
    }
    else {
         if ((max > 0) && (sscanf(str, "%"SCNu16"", val))  == 1 && (*val <= max)) {
            return 0;
         }
    }          
    return -1;
}

static int
parse32(char *str, struct names32 *names, size_t names_num, uint32_t max, uint32_t *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }

    if ((max > 0) && (sscanf(str, "%"SCNu32"", val)) == 1 && ((*val) <= max)) {
        return 0;
    }
    return -1;
}



const char *
ofputil_flow_format_to_string(enum ofp_ext_flow_format flow_format)
{
    switch (flow_format) {
    case OFPMT_STANDARD:
        return "openflow11";
    case NXFF_TUN_ID_FROM_COOKIE:
        return "tun_id_from_cookie";
    case EXT_MATCH:
        return "nxm";
    default:
        NOT_REACHED();
    }
}

int
ofputil_flow_format_from_string(const char *s)
{
    return (!strcmp(s, "openflow11") ? OFPMT_STANDARD
            : !strcmp(s, "tun_id_from_cookie") ? NXFF_TUN_ID_FROM_COOKIE
            : !strcmp(s, "nxm") ? EXT_MATCH
            : -1);
}

