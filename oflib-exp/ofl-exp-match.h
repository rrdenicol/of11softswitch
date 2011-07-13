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


#ifndef OFL_EXP_MATCH_H
#define OFL_EXP_MATCH_H 1

#include <sys/types.h>
#include <stdio.h>

#include "openflow/openflow.h"
#include "openflow/match-ext.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl.h"

struct ofl_ext_match {

    struct ofl_match_header header;      /* One of OFPMT_* */
    uint16_t length;                    /* Length of ofp_match */
    uint32_t wildcards;                 /* Wildcard fields. */
    struct flex_array *match_fields;    /* Match fields */   
};


int
ofl_exp_match_pack(struct ofl_match_header *src, struct ofp_match_header *dst);

ofl_err
ofl_exp_match_unpack(struct ofp_match_header *src, size_t *len, struct ofl_match_header **dst);

int     
ofl_exp_match_free(struct ofl_match_header *m);
    
size_t  
ofl_exp_match_length(struct ofl_match_header *m);

char *  
ofl_exp_match_to_string(struct ofl_match_header *m);

#endif /* OFL_EXP_MATCH_H */
