#ifndef INCREMENT_TABLE_ID_H
#define INCREMENT_TABLE_ID_H 1

#include "compiler.h"
#include "ofp-errors.h"

#include "simon.h"


struct ds;
struct flow;
struct flow_wildcards;
struct ofpbuf;
struct ofpact_increment_table_id;
struct ofputil_flow_mod;
struct nx_action_increment_table_id;

// Counters that may be incremented
#define TABLE_SPEC_INGRESS (1)
#define TABLE_SPEC_EGRESS  (2)


/* NXAST_INCREMENT_TABLE_ID helper functions.
 *
 * See include/openflow/nicira-ext.h for NXAST_INCREMENT_TABLE_ID specification.
 */
enum ofperr increment_table_id_check(const struct ofpact_increment_table_id *);
#if 0
enum ofperr increment_table_id_from_openflow(
    const struct nx_action_increment_table_id *,
    struct ofpbuf *ofpacts);

void increment_table_id_to_nxast(const struct ofpact_increment_table_id *,
                                 struct ofpbuf *openflow);
#endif
uint8_t increment_table_id_execute(const struct ofpact_increment_table_id *);

char *increment_table_id_parse(char *, struct ofpbuf *ofpacts);
void increment_table_id_format(const struct ofpact_increment_table_id *,
                               struct ds *);
//uint8_t get_table_val(void);

uint8_t get_table_counter_by_id(uint8_t table_id);

uint8_t get_table_counter_by_spec(uint8_t table_spec);

#endif /* increment_table_id.h */
