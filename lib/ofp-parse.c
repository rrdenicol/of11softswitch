/*
 * Copyright (c) 2010, 2011 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ofp-parse.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

#include "byte-order.h"
#include "dynamic-string.h"
#include "netdev.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "socket-util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofp_parse);

static uint32_t
str_to_u32(const char *str)
{
    char *tail;
    uint32_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static uint64_t
str_to_u64(const char *str)
{
    char *tail;
    uint64_t value;

    if (!str[0]) {
        ovs_fatal(0, "missing required numeric argument");
    }

    errno = 0;
    value = strtoull(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6])
{
    if (sscanf(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
        != ETH_ADDR_SCAN_COUNT) {
        ovs_fatal(0, "invalid mac address %s", str);
    }
}

static void
str_to_ip(const char *str_, uint32_t *ip, uint32_t *maskp)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in_addr in_addr;
    ovs_be32 mask;
    int retval;

    name = strtok_r(str, "/", &save_ptr);
    retval = name ? lookup_ip(name, &in_addr) : EINVAL;
    if (retval) {
        ovs_fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;

    netmask = strtok_r(NULL, "/", &save_ptr);
    if (netmask) {
        uint8_t o[4];
        if (sscanf(netmask, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
                   &o[0], &o[1], &o[2], &o[3]) == 4) {
            mask = htonl((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]);
        } else {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 32) {
                ovs_fatal(0, "%s: network prefix bits not between 1 and 32",
                          str);
            } else if (prefix == 32) {
                mask = htonl(UINT32_MAX);
            } else {
                mask = htonl(((1u << prefix) - 1) << (32 - prefix));
            }
        }
    } else {
        mask = htonl(UINT32_MAX);
    }
    *ip &= mask;

    if (maskp) {
        *maskp = mask;
    } else {
        if (mask != htonl(UINT32_MAX)) {
            ovs_fatal(0, "%s: netmask not allowed here", str_);
        }
    }

    free(str);
}


static bool
parse_port_name(const char *name, uint16_t *port)
{
    struct pair {
        const char *name;
        uint16_t value;
    };
    static const struct pair pairs[] = {
#define DEF_PAIR(NAME) {#NAME, OFPP_##NAME}
        DEF_PAIR(IN_PORT),
        DEF_PAIR(TABLE),
        DEF_PAIR(NORMAL),
        DEF_PAIR(FLOOD),
        DEF_PAIR(ALL),
        DEF_PAIR(CONTROLLER),
        DEF_PAIR(LOCAL),
        DEF_PAIR(NONE),
#undef DEF_PAIR
    };
    static const int n_pairs = ARRAY_SIZE(pairs);
    size_t i;

    for (i = 0; i < n_pairs; i++) {
        if (!strcasecmp(name, pairs[i].name)) {
            *port = pairs[i].value;
            return true;
        }
    }
    return false;
}


struct protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

static bool
parse_protocol(const char *name, const struct protocol **p_out)
{
    static const struct protocol protocols[] = {
        { "ip", ETH_TYPE_IP, 0 },
        { "arp", ETH_TYPE_ARP, 0 },
        { "icmp", ETH_TYPE_IP, IPPROTO_ICMP },
        { "tcp", ETH_TYPE_IP, IPPROTO_TCP },
        { "udp", ETH_TYPE_IP, IPPROTO_UDP },
        { "ipv6", ETH_TYPE_IPV6, 0 },
        { "ip6", ETH_TYPE_IPV6, 0 },
        { "icmp6", ETH_TYPE_IPV6, IPPROTO_ICMPV6 },
        { "tcp6", ETH_TYPE_IPV6, IPPROTO_TCP },
        { "udp6", ETH_TYPE_IPV6, IPPROTO_UDP },
    };
    const struct protocol *p;

    for (p = protocols; p < &protocols[ARRAY_SIZE(protocols)]; p++) {
        if (!strcmp(p->name, name)) {
            *p_out = p;
            return true;
        }
    }
    *p_out = NULL;
    return false;
}

#define FIELDS                                              \
    FIELD(F_TUN_ID,      "tun_id",      0)                  \
    FIELD(F_IN_PORT,     "in_port",     OFPFW_IN_PORT)        \
    FIELD(F_DL_VLAN,     "dl_vlan",     0)                  \
    FIELD(F_DL_VLAN_PCP, "dl_vlan_pcp", 0)                  \
    FIELD(F_DL_SRC,      "dl_src",      OFPFW_DL_SRC)         \
    FIELD(F_DL_DST,      "dl_dst",      OFPFW_DL_DST)         \
    FIELD(F_DL_TYPE,     "dl_type",     OFPFW_DL_TYPE)        \
    FIELD(F_NW_SRC,      "nw_src",      0)                  \
    FIELD(F_NW_DST,      "nw_dst",      0)                  \
    FIELD(F_NW_PROTO,    "nw_proto",    OFPFW_NW_PROTO)       \
    FIELD(F_NW_TOS,      "nw_tos",      OFPFW_NW_TOS)         \
    FIELD(F_TP_SRC,      "tp_src",      OFPFW_TP_SRC)         \
    FIELD(F_TP_DST,      "tp_dst",      OFPFW_TP_DST)         \
    FIELD(F_ICMP_TYPE,   "icmp_type",   OFPFW_TP_SRC)         \
    FIELD(F_ICMP_CODE,   "icmp_code",   OFPFW_TP_DST)         \
    FIELD(F_ARP_SHA,     "arp_sha",     OFPFW_ARP_SHA)        \
    FIELD(F_ARP_THA,     "arp_tha",     OFPFW_ARP_THA)        \
    FIELD(F_IPV6_SRC,    "ipv6_src",    0)                  \
    FIELD(F_IPV6_DST,    "ipv6_dst",    0)                  \
    FIELD(F_ND_TARGET,   "nd_target",   OFPFW_ND_TARGET)      \
    FIELD(F_ND_SLL,      "nd_sll",      OFPFW_ARP_SHA)        \
    FIELD(F_ND_TLL,      "nd_tll",      OFPFW_ARP_THA)

enum field_index {
#define FIELD(ENUM, NAME, WILDCARD) ENUM,
    FIELDS
#undef FIELD
    N_FIELDS
};

struct field {
    enum field_index index;
    const char *name;
    flow_wildcards_t wildcard;  /* OFPFW_* bit. */
};

static bool
parse_field_name(const char *name, const struct field **f_out)
{
    static const struct field fields[N_FIELDS] = {
#define FIELD(ENUM, NAME, WILDCARD) { ENUM, NAME, WILDCARD },
        FIELDS
#undef FIELD
    };
    const struct field *f;

    for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
        if (!strcmp(f->name, name)) {
            *f_out = f;
            return true;
        }
    }
    *f_out = NULL;
    return false;
}

static void
parse_field_value(struct cls_rule *rule, enum field_index index,
                  const char *value)
{
    uint8_t mac[ETH_ADDR_LEN];
    ovs_be64 tun_id, tun_mask;
    ovs_be32 ip, mask;
    struct in6_addr ipv6, ipv6_mask;
    uint16_t port_no;

    switch (index) {
    case F_TUN_ID:
        str_to_tun_id(value, &tun_id, &tun_mask);
        cls_rule_set_tun_id_masked(rule, tun_id, tun_mask);
        break;

    case F_IN_PORT:
        if (!parse_port_name(value, &port_no)) {
            port_no = atoi(value);
        }
        if (port_no == OFPP_LOCAL) {
            port_no = ODPP_LOCAL;
        }
        cls_rule_set_in_port(rule, port_no);
        break;

    case F_DL_VLAN:
        cls_rule_set_dl_vlan(rule, htons(str_to_u32(value)));
        break;

    case F_DL_VLAN_PCP:
        cls_rule_set_dl_vlan_pcp(rule, str_to_u32(value));
        break;

    case F_DL_SRC:
        str_to_mac(value, mac);
        cls_rule_set_dl_src(rule, mac);
        break;

    case F_DL_DST:
        str_to_mac(value, mac);
        cls_rule_set_dl_dst(rule, mac);
        break;

    case F_DL_TYPE:
        cls_rule_set_dl_type(rule, htons(str_to_u32(value)));
        break;

    case F_NW_SRC:
        str_to_ip(value, &ip, &mask);
        cls_rule_set_nw_src_masked(rule, ip, mask);
        break;

    case F_NW_DST:
        str_to_ip(value, &ip, &mask);
        cls_rule_set_nw_dst_masked(rule, ip, mask);
        break;

    case F_NW_PROTO:
        cls_rule_set_nw_proto(rule, str_to_u32(value));
        break;

    case F_NW_TOS:
        cls_rule_set_nw_tos(rule, str_to_u32(value));
        break;

    case F_TP_SRC:
        cls_rule_set_tp_src(rule, htons(str_to_u32(value)));
        break;

    case F_TP_DST:
        cls_rule_set_tp_dst(rule, htons(str_to_u32(value)));
        break;

    case F_ICMP_TYPE:
        cls_rule_set_icmp_type(rule, str_to_u32(value));
        break;

    case F_ICMP_CODE:
        cls_rule_set_icmp_code(rule, str_to_u32(value));
        break;

    case F_ARP_SHA:
        str_to_mac(value, mac);
        cls_rule_set_arp_sha(rule, mac);
        break;

    case F_ARP_THA:
        str_to_mac(value, mac);
        cls_rule_set_arp_tha(rule, mac);
        break;

    case F_IPV6_SRC:
        str_to_ipv6(value, &ipv6, &ipv6_mask);
        cls_rule_set_ipv6_src_masked(rule, &ipv6, &ipv6_mask);
        break;

    case F_IPV6_DST:
        str_to_ipv6(value, &ipv6, &ipv6_mask);
        cls_rule_set_ipv6_dst_masked(rule, &ipv6, &ipv6_mask);
        break;

    case F_ND_TARGET:
        str_to_ipv6(value, &ipv6, NULL);
        cls_rule_set_nd_target(rule, ipv6);
        break;

    case F_ND_SLL:
        str_to_mac(value, mac);
        cls_rule_set_arp_sha(rule, mac);
        break;

    case F_ND_TLL:
        str_to_mac(value, mac);
        cls_rule_set_arp_tha(rule, mac);
        break;

    case N_FIELDS:
        NOT_REACHED();
    }
}


/* Convert 'string' (as described in the Flow Syntax section of the ovs-ofctl
 * man page) into 'pf'.  If 'actions' is specified, an action must be in
 * 'string' and may be expanded or reallocated. */
void
parse_ofp_str(struct flow_mod *fm, uint8_t *table_idx,
              struct ofpbuf *actions, char *string)
{
    char *save_ptr = NULL;
    char *name;

    if (table_idx) {
        *table_idx = 0xff;
    }
    cls_rule_init_catchall(&fm->cr, OFP_DEFAULT_PRIORITY);
    fm->cookie = htonll(0);
    fm->command = UINT16_MAX;
    fm->idle_timeout = OFP_FLOW_PERMANENT;
    fm->hard_timeout = OFP_FLOW_PERMANENT;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = 0;
    if (actions) {
        char *act_str = strstr(string, "action");
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }
        *act_str = '\0';

        act_str = strchr(act_str + 1, '=');
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }

        act_str++;

        str_to_action(act_str, actions);
        fm->actions = actions->data;
        fm->n_actions = actions->size / sizeof(union ofp_action);
    } else {
        fm->actions = NULL;
        fm->n_actions = 0;
    }
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            cls_rule_set_dl_type(&fm->cr, htons(p->dl_type));
            if (p->nw_proto) {
                cls_rule_set_nw_proto(&fm->cr, p->nw_proto);
            }
        } else {
            const struct field *f;
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ovs_fatal(0, "field %s missing value", name);
            }

            if (table_idx && !strcmp(name, "table")) {
                *table_idx = atoi(value);
            } else if (!strcmp(name, "out_port")) {
                fm->out_port = atoi(value);
            } else if (!strcmp(name, "priority")) {
                fm->cr.priority = atoi(value);
            } else if (!strcmp(name, "idle_timeout")) {
                fm->idle_timeout = atoi(value);
            } else if (!strcmp(name, "hard_timeout")) {
                fm->hard_timeout = atoi(value);
            } else if (!strcmp(name, "cookie")) {
                fm->cookie = htonll(str_to_u64(value));
            } else if (parse_field_name(name, &f)) {
                if (!strcmp(value, "*") || !strcmp(value, "ANY")) {
                    if (f->wildcard) {
                        fm->cr.wc.wildcards |= f->wildcard;
                        cls_rule_zero_wildcarded_fields(&fm->cr);
                    } else if (f->index == F_NW_SRC) {
                        cls_rule_set_nw_src_masked(&fm->cr, 0, 0);
                    } else if (f->index == F_NW_DST) {
                        cls_rule_set_nw_dst_masked(&fm->cr, 0, 0);
                    } else if (f->index == F_IPV6_SRC) {
                        cls_rule_set_ipv6_src_masked(&fm->cr,
                                &in6addr_any, &in6addr_any);
                    } else if (f->index == F_IPV6_DST) {
                        cls_rule_set_ipv6_dst_masked(&fm->cr,
                                &in6addr_any, &in6addr_any);
                    } else if (f->index == F_DL_VLAN) {
                        cls_rule_set_any_vid(&fm->cr);
                    } else if (f->index == F_DL_VLAN_PCP) {
                        cls_rule_set_any_pcp(&fm->cr);
                    } else {
                        NOT_REACHED();
                    }
                } else {
                    parse_field_value(&fm->cr, f->index, value);
                }
            } else if (!strncmp(name, "reg", 3)
                       && isdigit((unsigned char) name[3])) {
                unsigned int reg_idx = atoi(name + 3);
                if (reg_idx >= FLOW_N_REGS) {
                    ovs_fatal(0, "only %d registers supported", FLOW_N_REGS);
                }
                parse_reg_value(&fm->cr, reg_idx, value);
            } else {
                ovs_fatal(0, "unknown keyword %s", name);
            }
        }
    }
}

/* Parses 'string' as an OFPT_FLOW_MOD or NXT_FLOW_MOD with command 'command'
 * (one of OFPFC_*) and appends the parsed OpenFlow message to 'packets'.
 * '*cur_format' should initially contain the flow format currently configured
 * on the connection; this function will add a message to change the flow
 * format and update '*cur_format', if this is necessary to add the parsed
 * flow. */
void
parse_ofp_flow_mod_str(struct list *packets, enum nx_flow_format *cur_format,
                       char *string, uint16_t command)
{
    bool is_del = command == OFPFC_DELETE || command == OFPFC_DELETE_STRICT;
    enum nx_flow_format min_format, next_format;
    struct ofpbuf actions;
    struct ofpbuf *ofm;
    struct flow_mod fm;

    ofpbuf_init(&actions, 64);
    parse_ofp_str(&fm, NULL, is_del ? NULL : &actions, string);
    fm.command = command;

    min_format = ofputil_min_flow_format(&fm.cr, true, fm.cookie);
    next_format = MAX(*cur_format, min_format);
    if (next_format != *cur_format) {
        struct ofpbuf *sff = ofputil_make_set_flow_format(next_format);
        list_push_back(packets, &sff->list_node);
        *cur_format = next_format;
    }

    ofm = ofputil_encode_flow_mod(&fm, *cur_format);
    list_push_back(packets, &ofm->list_node);

    ofpbuf_uninit(&actions);
}


