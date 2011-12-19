/* Copyright (c) 2011, CPqD, Brasil
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

#ifndef MATCH_EXT_H
#define MATCH_EXT_H 1

#include "openflow.h"
#include "../../lib/flex-array.h"

/* Flexible flow specifications (aka NXM = Nicira Extended Match).
 *
 * OpenFlow 1.0 has "struct ofp_match" for specifying flow matches.  This
 * structure is fixed-length and hence difficult to extend.  This section
 * describes a more flexible, variable-length flow match, called "nx_match" for
 * short, that is also supported by Open vSwitch.  This section also defines a
 * replacement for each OpenFlow message that includes struct ofp_match.
 *
 *
 * Format
 * ======
 *
 * An nx_match is a sequence of zero or more "nxm_entry"s, which are
 * type-length-value (TLV) entries, each 5 to 259 (inclusive) bytes long.
 * "nxm_entry"s are not aligned on or padded to any multibyte boundary.  The
 * first 4 bytes of an nxm_entry are its "header", followed by the entry's
 * "body".
 *
 * An nxm_entry's header is interpreted as a 32-bit word in network byte order:
 *
 * |<-------------------- nxm_type ------------------>|
 * |                                                  |
 * |31                              16 15            9| 8 7                0
 * +----------------------------------+---------------+--+------------------+
 * |            nxm_vendor            |   nxm_field   |hm|    nxm_length    |
 * +----------------------------------+---------------+--+------------------+
 *
 * The most-significant 23 bits of the header are collectively "nxm_type".
 * Bits 16...31 are "nxm_vendor", one of the NXM_VENDOR_* values below.  Bits
 * 9...15 are "nxm_field", which is a vendor-specific value.  nxm_type normally
 * designates a protocol header, such as the Ethernet type, but it can also
 * refer to packet metadata, such as the switch port on which a packet arrived.
 *
 * Bit 8 is "nxm_hasmask" (labeled "hm" above for space reasons).  The meaning
 * of this bit is explained later.
 *
 * The least-significant 8 bits are "nxm_length", a positive integer.  The
 * length of the nxm_entry, including the header, is exactly 4 + nxm_length
 * bytes.
 *
 * For a given nxm_vendor, nxm_field, and nxm_hasmask value, nxm_length is a
 * constant.  It is included only to allow software to minimally parse
 * "nxm_entry"s of unknown types.  (Similarly, for a given nxm_vendor,
 * nxm_field, and nxm_length, nxm_hasmask is a constant.)
 *
 *
 * Semantics
 * =========
 *
 * A zero-length nx_match (one with no "nxm_entry"s) matches every packet.
 *
 * An nxm_entry places a constraint on the packets matched by the nx_match:
 *
 *   - If nxm_hasmask is 0, the nxm_entry's body contains a value for the
 *     field, called "nxm_value".  The nx_match matches only packets in which
 *     the field equals nxm_value.
 *
 *   - If nxm_hasmask is 1, then the nxm_entry's body contains a value for the
 *     field (nxm_value), followed by a bitmask of the same length as the
 *     value, called "nxm_mask".  For each 1-bit in position J in nxm_mask, the
 *     nx_match matches only packets for which bit J in the given field's value
 *     matches bit J in nxm_value.  A 0-bit in nxm_mask causes the
 *     corresponding bits in nxm_value and the field's value to be ignored.
 *     (The sense of the nxm_mask bits is the opposite of that used by the
 *     "wildcards" member of struct ofp_match.)
 *
 *     When nxm_hasmask is 1, nxm_length is always even.
 *
 *     An all-zero-bits nxm_mask is equivalent to omitting the nxm_entry
 *     entirely.  An all-one-bits nxm_mask is equivalent to specifying 0 for
 *     nxm_hasmask.
 *
 * When there are multiple "nxm_entry"s, all of the constraints must be met.
 *
 *
 * Mask Restrictions
 * =================
 *
 * Masks may be restricted:
 *
 *   - Some nxm_types may not support masked wildcards, that is, nxm_hasmask
 *     must always be 0 when these fields are specified.  For example, the
 *     field that identifies the port on which a packet was received may not be
 *     masked.
 *
 *   - Some nxm_types that do support masked wildcards may only support certain
 *     nxm_mask patterns.  For example, fields that have IPv4 address values
 *     may be restricted to CIDR masks.
 *
 * These restrictions should be noted in specifications for individual fields.
 * A switch may accept an nxm_hasmask or nxm_mask value that the specification
 * disallows, if the switch correctly implements support for that nxm_hasmask
 * or nxm_mask value.  A switch must reject an attempt to set up a flow that
 * contains a nxm_hasmask or nxm_mask value that it does not support.
 *
 *
 * Prerequisite Restrictions
 * =========================
 *
 * The presence of an nxm_entry with a given nxm_type may be restricted based
 * on the presence of or values of other "nxm_entry"s.  For example:
 *
 *   - An nxm_entry for nxm_type=NXM_OF_IP_TOS is allowed only if it is
 *     preceded by another entry with nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0,
 *     and nxm_value=0x0800.  That is, matching on the IP source address is
 *     allowed only if the Ethernet type is explicitly set to IP.
 *
 *   - An nxm_entry for nxm_type=NXM_OF_TCP_SRC is allowed only if it is preced
 *     by an entry with nxm_type=NXM_OF_ETH_TYPE, nxm_hasmask=0,
 *     nxm_value=0x0800 and another with nxm_type=NXM_OF_IP_PROTO,
 *     nxm_hasmask=0, nxm_value=6, in that order.  That is, matching on the TCP
 *     source port is allowed only if the Ethernet type is IP and the IP
 *     protocol is TCP.
 *
 * These restrictions should be noted in specifications for individual fields.
 * A switch may implement relaxed versions of these restrictions.  A switch
 * must reject an attempt to set up a flow that violates its restrictions.
 *
 *
 * Ordering Restrictions
 * =====================
 *
 * An nxm_entry that has prerequisite restrictions must appear after the
 * "nxm_entry"s for its prerequisites.  Ordering of "nxm_entry"s within an
 * nx_match is not otherwise constrained.
 *
 * Any given nxm_type may appear in an nx_match at most once.
 *
 *
 * nxm_entry Examples
 * ==================
 *
 * These examples show the format of a single nxm_entry with particular
 * nxm_hasmask and nxm_length values.  The diagrams are labeled with field
 * numbers and byte indexes.
 *
 *
 * 8-bit nxm_value, nxm_hasmask=1, nxm_length=1:
 *
 *  0          3  4   5
 * +------------+---+---+
 * |   header   | v | m |
 * +------------+---+---+
 *
 *
 * 16-bit nxm_value, nxm_hasmask=0, nxm_length=2:
 *
 *  0          3 4    5
 * +------------+------+
 * |   header   | value|
 * +------------+------+
 *
 *
 * 32-bit nxm_value, nxm_hasmask=0, nxm_length=4:
 *
 *  0          3 4           7
 * +------------+-------------+
 * |   header   |  nxm_value  |
 * +------------+-------------+
 *
 *
 * 48-bit nxm_value, nxm_hasmask=0, nxm_length=6:
 *
 *  0          3 4                9
 * +------------+------------------+
 * |   header   |     nxm_value    |
 * +------------+------------------+
 *
 *
 * 48-bit nxm_value, nxm_hasmask=1, nxm_length=12:
 *
 *  0          3 4                9 10              15
 * +------------+------------------+------------------+
 * |   header   |     nxm_value    |      nxm_mask    |
 * +------------+------------------+------------------+
 *
 *
 * Error Reporting
 * ===============
 *
 * A switch should report an error in an nx_match using error type
 * OFPET_BAD_REQUEST and one of the NXBRC_NXM_* codes.  Ideally the switch
 * should report a specific error code, if one is assigned for the particular
 * problem, but NXBRC_NXM_INVALID is also available to report a generic
 * nx_match error.
 */

#define NXM_HEADER__(VENDOR, FIELD, HASMASK, LENGTH) \
    (((VENDOR) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
#define NXM_HEADER(VENDOR, FIELD, LENGTH) \
    NXM_HEADER__(VENDOR, FIELD, 0, LENGTH)
#define NXM_HEADER_W(VENDOR, FIELD, LENGTH) \
    NXM_HEADER__(VENDOR, FIELD, 1, (LENGTH) * 2)

#define NXM_HEADER_VL(VENDOR,FIELD) \
    NXM_HEADER__(VENDOR,FIELD,0,0)

#define NXM_HEADER_VL_W(VENDOR,FIELD) \
   NXM_HEADER__(VENDOR,FIELD,1,0)
   
#define NXM_VENDOR(HEADER) ((HEADER) >> 16)
#define NXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define NXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define NXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define NXM_LENGTH(HEADER) ((HEADER) & 0xff)
#define VENDOR_FROM_TYPE(TYPE) ((TYPE) >> 7)
#define FIELD_FROM_TYPE(TYPE)  ((TYPE) & 0x7f)

#define NXM_MAKE_WILD_HEADER(HEADER) \
        NXM_HEADER_W(NXM_VENDOR(HEADER), NXM_FIELD(HEADER), NXM_LENGTH(HEADER))

/* ## ------------------------------- ## */
/* ## OpenFlow 1.0-compatible fields. ## */
/* ## ------------------------------- ## */

/* Physical or virtual port on which the packet was received.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer. */
#define    TLV_EXT_IN_PORT   NXM_HEADER    (0x0000, 0, 4)
#define    TLV_EXT_IN_PORT_W NXM_HEADER_W  (0x0000, 0, 4)  

/* VLAN id. */
#define    TLV_EXT_DL_VLAN NXM_HEADER  (0x0000, 1, 2)
#define    TLV_EXT_DL_VLAN_W NXM_HEADER_W  (0x0000, 1, 2) 

 /* VLAN priority. */
#define    TLV_EXT_DL_VLAN_PCP NXM_HEADER  (0x0000, 2, 1)
#define    TLV_EXT_DL_VLAN_PCP_W NXM_HEADER_W  (0x0000, 2, 1)

/* Ethernet frame type. */
#define    TLV_EXT_DL_TYPE     NXM_HEADER    (0x0000, 3, 2)
#define    TLV_EXT_DL_TYPE_W   NXM_HEADER_W  (0x0000, 3, 2)

/* IP ToS (DSCP field, 6 bits). */
#define    TLV_EXT_NW_TOS      NXM_HEADER    (0x0000, 4, 1)
#define    TLV_EXT_NW_TOS_W    NXM_HEADER_W  (0x0000, 4, 1)  

/* IP protocol. */
#define    TLV_EXT_NW_PROTO   NXM_HEADER  (0x0000, 5, 1) 
#define    TLV_EXT_NW_PROTO_W   NXM_HEADER_W  (0x0000, 5, 1) 

/* TCP/UDP/SCTP source port. */
#define    TLV_EXT_TP_SRC      NXM_HEADER  (0x0000, 6, 2)
#define    TLV_EXT_TP_SRC_W    NXM_HEADER_W  (0x0000, 6, 2)  

 /* TCP/UDP/SCTP destination port. */ 
#define    TLV_EXT_TP_DST    NXM_HEADER    (0x0000, 7, 2)
#define    TLV_EXT_TP_DST_W  NXM_HEADER_W  (0x0000, 7, 2)   

/* Ethernet destination address.*/
#define    TLV_EXT_DL_DST   NXM_HEADER  (0x0000,8,6) 
#define    TLV_EXT_DL_DST_W NXM_HEADER_W(0X0000,8,6) 

/* Ethernet source address.*/
#define    TLV_EXT_DL_SRC   NXM_HEADER  (0x0000, 9,6)
#define    TLV_EXT_DL_SRC_W NXM_HEADER_W(0X0000,9,6) 

 /* IP source address. */
#define    TLV_EXT_IP_SRC      NXM_HEADER  (0x0000,10, 4)
#define    TLV_EXT_IP_SRC_W  NXM_HEADER_W  (0x0000,10, 4) 

/* IP destination address. */
#define    TLV_EXT_IP_DST     NXM_HEADER  (0x0000,11 , 4) 
#define    TLV_EXT_IP_DST_W     NXM_HEADER_W  (0x0000,11 , 4) 


/* ## ------------------------------- ## */
/* ## OpenFlow 1.1-compatible fields. ## */
/* ## ------------------------------- ## */

/* MPLS label. */
#define TLV_EXT_MPLS_LABEL NXM_HEADER (0x0001, 0, 3)
#define TLV_EXT_MPLS_LABEL_W NXM_HEADER_W (0x0001, 0, 3)  

/* MPLS TC. */
#define TLV_EXT_MPLS_TC NXM_HEADER     (0x0001, 1, 1)
#define TLV_EXT_MPLS_TC_W NXM_HEADER_W (0x0001, 1, 1)  

/* Metadata passed btw tables. */
#define TLV_EXT_METADATA NXM_HEADER     (0x0001, 2, 8)
#define TLV_EXT_METADATA_W NXM_HEADER_W (0x0001, 2, 8)



/* ## ------------------------------- ## */
/* ## IPv6 compatible fields. ## */
/* ## ------------------------------- ## */

/* IPv6 source address */
#define TLV_EXT_IPV6_SRC NXM_HEADER (0x0002, 0, 16)
#define TLV_EXT_IPV6_SRC_W NXM_HEADER_W(0x0002, 0, 16)

/* IPv6 destination address*/
#define TLV_EXT_IPV6_DST NXM_HEADER (0x0002, 1, 16) 
#define TLV_EXT_IPV6_DST_W NXM_HEADER_W(0x0002, 1, 16)

/* ICMPv6 message type field */
#define TLV_EXT_ICMPV6_TYPE NXM_HEADER (0x0002, 2, 1) 

/* ICMPv6 type code */
#define TLV_EXT_ICMPV6_CODE NXM_HEADER (0x0002, 3, 1) 

/* Flow Label, 20-bits*/
#define TLV_EXT_IPV6_FLOW NXM_HEADER (0x0002, 4, 4)
#define TLV_EXT_IPV6_FLOW_W NXM_HEADER_W (0x0002, 4, 4)

/* Traffic Class */
#define TLV_EXT_IPV6_TC NXM_HEADER (0x0002, 5, 1)
#define TLV_EXT_IPV6_TC_W NXM_HEADER_W (0x0002, 5, 1)

/* IPv6 Hop-by-Hop EH ID*/
#define TLV_EXT_IPV6_HBH_ID NXM_HEADER (0x0002, 8, 1)
#define TLV_EXT_IPV6_HBH_ID_W NXM_HEADER_W (0x0002, 8, 1)  

#define TLV_EXT_IPV6_HBH_OPT_CODE NXM_HEADER (0x0002, 9, 1) 

#define TLV_EXT_IPV6_HBH_OPT_VALUE NXM_HEADER_VL (0x0002, 10) 

/* IPv6 Destination Option EH ID*/
#define TLV_EXT_IPV6_DOH_ID NXM_HEADER (0x0002, 16, 1)
#define TLV_EXT_IPV6_DOH_ID_W NXM_HEADER_W (0x0002, 16, 1)

#define TLV_EXT_IPV6_DOH_OPT_CODE NXM_HEADER (0x0002, 17, 1)

#define TLV_EXT_IPV6_DOH_OPT_VALUE NXM_HEADER_VL (0x0002, 18)


/* IPv6 Routing EH ID*/ 
#define TLV_EXT_IPV6_RH_ID NXM_HEADER (0x0002, 24, 1)
#define TLV_EXT_IPV6_RH_ID_W NXM_HEADER_W (0x0002, 24, 1)

#define TLV_EXT_IPV6_RH_ADDRESS NXM_HEADER (0x0002, 25, 16)

/* IPv6 Fragmentation EH ID*/
#define TLV_EXT_IPV6_FH_ID NXM_HEADER (0x0002, 32, 1)
#define TLV_EXT_IPV6_FH_ID_W NXM_HEADER_W (0x0002, 32, 1)

/* IPv6 Authentication EH ID*/ 
#define TLV_EXT_IPV6_AH_ID NXM_HEADER (0x0002, 40, 1)
#define TLV_EXT_IPV6_AH_ID_W NXM_HEADER_W (0x0002, 40, 1)

/* IPv6 Encapsulating Security Payload */ 
#define TLV_EXT_IPV6_ESP_ID NXM_HEADER (0x0002, 48, 1) 

/* IPv6 Mobility EH */
#define TLV_EXT_IPV6_MH_ID NXM_HEADER (0x0002, 56, 1) 

#define EXTENDED_MATCH_ID 0x00005678

struct ofp_ext_header{
    struct ofp_header header;
    uint32_t vendor;            /* EXTENDED_MATCH_ID. */
    uint32_t subtype;           /* One of ofp_extension_commands */
};
OFP_ASSERT(sizeof(struct ofp_ext_header) == 16);


/* Values for the 'subtype' member of struct ext_header. */
enum ofp_ext_type {

    /* Flexible flow specification (aka NXM = Nicira Extended Match). */
    EXT_SET_FLOW_FORMAT,        /* Set flow format. */
    EXT_FLOW_MOD,               /* Analogous to OFPT_FLOW_MOD. */
    EXT_FLOW_REMOVED,            /* Analogous to OFPT_FLOW_REMOVED. */
    
    OFPST_EXT_FLOW
};

struct ext_match
{
    struct ofp_match_header header;
    uint8_t pad[4];                 /* Align to 64 bits */
    struct flex_array match_fields; /* Match fields */   

} ;

OFP_ASSERT( sizeof(struct ext_match) == 16);

/* ## --------------------- ## */
/* ## Requests and replies. ## */
/* ## --------------------- ## */

enum ofp_ext_flow_format {
    NXFF_OPENFLOW10 = OFPMT_STANDARD,         /* Standard OpenFlow 1.0 compatible. */
    NXFF_TUN_ID_FROM_COOKIE = 1, /* OpenFlow 1.0, plus obtain tunnel ID from
                                  * cookie. */
    EXT_MATCH= 2                 /* Nicira extended match. */
};

/* EXT_SET_FLOW_FORMAT request. */
struct ofp_ext_set_flow_format {
    struct ofp_header header;
    uint32_t subtype;           /* NXT_SET_FLOW_FORMAT. */
    uint32_t format;            /* One of NXFF_*. */
};
OFP_ASSERT(sizeof(struct ofp_ext_set_flow_format) == 16);


/* NXT_FLOW_MOD (analogous to OFPT_FLOW_MOD). */
struct ofp_ext_flow_mod {
    struct ofp_ext_header header;
    uint64_t cookie;              /* Opaque controller-issued identifier. */
    uint64_t cookie_mask;        /* Mask used to restrict the cookie bits
                                    that must match when the command is
                                    OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                    of 0 indicates no restriction. */

    uint8_t table_id;           /* ID of the table */
    uint8_t command;             /* One of OFPFC_*. */
    uint16_t idle_timeout;        /* Idle time before discarding (seconds). */
    uint16_t hard_timeout;        /* Max time before discarding (seconds). */
    uint16_t priority;            /* Priority level of flow entry. */
    uint32_t buffer_id;           /* Buffered packet to apply to (or -1).
                                     Not meaningful for OFPFC_DELETE*. */
    uint32_t out_port;            /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_NONE
                                     indicates no restriction. */
    uint32_t  out_group;           /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output group. A value of OFPG_ANY
                                     indicates no restriction. */
    uint16_t flags;                /* One of OFPFF_*. */
    uint8_t pad[2];
    struct ext_match *match;	       /* Extended match */
    struct ofp_instruction instructions[0]; /* Instruction set. */
};


/* NXT_FLOW_REMOVED (analogous to OFPT_FLOW_REMOVED). */
struct ofp_ext_flow_removed {
    struct ofp_ext_header header;
    uint64_t cookie;          /* Opaque controller-issued identifier. */
    uint16_t priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t table_id;         /* ID of the table */
    uint32_t duration_sec;    /* Time flow was alive in seconds. */
    uint32_t duration_nsec;   /* Time flow was alive in nanoseconds beyond
                                 duration_sec. */
    uint16_t idle_timeout;    /* Idle timeout from original flow mod. */
    uint8_t pad[2];           /* Align to 64-bits. */
    uint64_t packet_count;
    uint64_t byte_count;
    struct ext_match match;
   
};

/* Nicira vendor stats request of type NXST_FLOW (analogous to OFPST_FLOW
 * request). */
struct ofp_ext_flow_stats_request {
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats),
                                 0xff for all tables. */
    uint8_t pad[7];               /* Align to 64 bits. */
    uint32_t out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
    uint32_t out_group;       /* Require matching entries to include this
                                 as an output group.  A value of OFPG_ANY
                                 indicates no restriction. */
    uint64_t cookie;          /* Require matching entries to contain this
                                 cookie value */
    uint64_t cookie_mask;     /* Mask used to restrict the cookie bits that
                                 must match. A value of 0 indicates
                                 no restriction. */
    struct ext_match match;   /* Fields to match. */
   
};

/* Body for Nicira vendor stats reply of type NXST_FLOW (analogous to
 * OFPST_FLOW reply). */
struct ofp_ext_flow_stats {
    
    uint16_t length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    uint32_t duration_sec;    /* Time flow has been alive in seconds. */
    uint32_t duration_nsec;   /* Time flow has been alive in nanoseconds
                                 beyond duration_sec. */
    uint16_t priority;        /* Priority of the entry. Only meaningful
                                 when this is not an exact-match entry. */
    uint16_t idle_timeout;    /* Number of seconds idle before expiration. */
    uint16_t hard_timeout;    /* Number of seconds before expiration. */
    uint8_t pad2[6];          /* Align to 64 bits. */
    uint64_t cookie;          /* Opaque controller-issued identifier. */
    uint64_t packet_count;    /* Number of packets in flow. */
    uint64_t byte_count;      /* Number of bytes in flow. */
    struct ext_match *match;   /* Description of fields. */
    struct ofp_instruction instructions[0]; /* Instruction set. */
};
OFP_ASSERT(sizeof(struct ofp_ext_flow_stats) == 52);

/* Nicira vendor stats request of type NXST_AGGREGATE (analogous to
 * OFPST_AGGREGATE request). */
struct ofp_ext_aggregate_stats_request {
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 0xff for all tables. */
    uint8_t pad;           /* Align to 64 bits. */
    uint16_t out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_NONE
                                 indicates no restriction. */
    uint32_t out_group;       /* Require matching entries to include this
                                 as an output group.  A value of OFPG_ANY
                                 indicates no restriction. */
    uint64_t cookie;          /* Require matching entries to contain this
                                 cookie value */
    uint64_t cookie_mask;     /* Mask used to restrict the cookie bits that
                                 must match. A value of 0 indicates
                                 no restriction. */
    struct ext_match match;   /* Fields to match. */
   
};


#endif /* openflow/match-ext.h */
