#ifndef LEARN_LEARN_H
#define LEARN_LEARN_H 1

#include "compiler.h"
#include "ofp-util.h"
#include "ofp-errors.h"

struct ds;
struct flow;
struct flow_wildcards;
struct ofpact;
struct ofpbuf;
struct ofpact_learn_learn;
struct ofputil_flow_mod;
struct nx_action_learn_learn;

struct vtable_ctx;

/* NXAST_LEARN_LEARN helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_LEARN_LEARN specification.
 */

#define LEARN_USING_RULE_TABLE            2
#define LEARN_USING_INGRESS_ATOMIC_TABLE  3
#define LEARN_USING_EGRESS_ATOMIC_TABLE   4

#if 0
enum ofperr learn_learn_from_openflow(const struct nx_action_learn_learn *,
                                      struct ofpbuf *ofpacts);

void learn_learn_to_nxast(const struct ofpact_learn_learn *,
                           struct ofpbuf *openflow);
#endif

void populate_deferral_values(struct ofpact_learn_learn *act,
                              const struct flow *flow);
void do_deferral(struct ofpact *ofpacts, uint32_t ofpacts_len,
                 const struct flow *flow);

enum ofperr learn_learn_check(const struct ofpact_learn_learn * learn,
                              struct flow * flow, ofp_port_t max_ports,
			      uint8_t table_id, uint8_t n_tables,
			      enum ofputil_protocol *usable_protocols);

void learn_learn_execute(const struct ofpact_learn_learn *learn, const struct flow *flow,
                         struct ofputil_flow_mod *fm, struct ofpbuf *ofpacts, uint8_t rule_table,
			 struct vtable_ctx *vtable_ctx);

void learn_learn_mask(const struct ofpact_learn_learn *learn,
		      struct flow_wildcards *wc);

char *learn_learn_parse(char *arg, struct ofpbuf *ofpacts,
			enum ofputil_protocol *usable_protocols) OVS_WARN_UNUSED_RESULT;
void learn_learn_format(const struct ofpact_learn_learn *, struct ds *);

#endif /* learn_learn.h */
