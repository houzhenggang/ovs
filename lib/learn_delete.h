/*
 * Copyright (c) 2011, 2012, 2013 Nicira, Inc.
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

#ifndef LEARN_DELETE_H
#define LEARN_DELETE_H 1

#include "compiler.h"
#include "ofp-errors.h"
#include "ofp-util.h"

struct ds;
struct flow;
struct flow_wildcards;
struct ofpbuf;
struct ofpact_learn_delete;
struct ofputil_flow_mod;
struct nx_action_learn_delete;

/* NXAST_DELETE_LEARN helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_DELETE_LEARN specification.
 */

#define DELETE_USING_RULE_TABLE  2
#define DELETE_USING_INGRESS_ATOMIC_TABLE 3
#define DELETE_USING_EGRESS_ATOMIC_TABLE 4

//enum ofperr learn_delete_from_openflow(const struct nx_action_learn_delete *,
//                                       struct ofpbuf *ofpacts);
enum ofperr learn_delete_check(const struct ofpact_learn_delete *,
                               const struct flow *);
//void learn_delete_to_nxast(const struct ofpact_learn_delete *,
//                           struct ofpbuf *openflow);
void learn_delete_execute(const struct ofpact_learn_delete *learn,
                          const struct flow *flow, struct ofputil_flow_mod *fm,
                          struct ofpbuf *ofpacts, uint8_t rule_table);

void learn_delete_mask(const struct ofpact_learn_delete *,
                       struct flow_wildcards *);

char *learn_delete_parse(char *arg, struct ofpbuf *ofpacts, 
            enum ofputil_protocol *) OVS_WARN_UNUSED_RESULT;
void learn_delete_format(const struct ofpact_learn_delete *, struct ds *);

#endif /* learn_delete.h */
