#ifndef TIMEOUT_ACT_H
#define TIMEOUT_ACT_H 1

#include "compiler.h"
#include "ofp-errors.h"
#include "ofp-util.h"

struct ds;
struct flow;
struct flow_wildcards;
struct ofpbuf;
struct ofpact_timeout_act;
struct ofputil_flow_mod;
struct nx_action_timeout_act;
struct rule;

/* NXAST_TIMEOUT_ACT helper functions */

//enum ofperr timeout_act_from_openflow(const struct nx_action_timeout_act *,
//                                      struct ofpbuf *ofpacts);
enum ofperr timeout_act_check(const struct ofpact_timeout_act *,
                              struct flow *, ofp_port_t max_ports,
                              uint8_t table_id, uint8_t n_tables,
                              enum ofputil_protocol *usable_protocols);
//void timeout_act_to_nxast(const struct ofpact_timeout_act *,
//                          struct ofpbuf *openflow);

//void timeout_act_execute(const struct ofpact_timeout_act *, struct flow *,
//                         struct rule *);

char *timeout_act_parse(char *, struct ofpbuf *ofpacts,
                        enum ofputil_protocol *usable_protocols)
                        OVS_WARN_UNUSED_RESULT;
void timeout_act_format(const struct ofpact_timeout_act *, struct ds *);

#endif /* timeout_act.h */
