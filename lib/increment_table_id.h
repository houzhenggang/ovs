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
#define TABLE_SPEC_INGRESS (0x01)
#define TABLE_SPEC_EGRESS  (0x02)

#define TABLE_SPEC_BOTH (TABLE_SPEC_INGRESS | TABLE_SPEC_EGRESS)

/* Variable type for our table IDs, which must match the atomic type. */
typedef uint64_t vtable_id;

/* Format string for the atomic ID type */
#define PRIvtable PRIu64


/* NXAST_INCREMENT_TABLE_ID helper functions.
 *
 * See include/ofp-actions.h for NXAST_INCREMENT_TABLE_ID specification.
 */
enum ofperr increment_table_id_check(const struct ofpact_increment_table_id *);

vtable_id increment_table_id_execute(const struct ofpact_increment_table_id *);

char *increment_table_id_parse(char *, struct ofpbuf *ofpacts);
void increment_table_id_format(const struct ofpact_increment_table_id *,
                               struct ds *);

vtable_id get_table_counter_by_id(vtable_id table_id);

vtable_id get_table_counter_by_spec(vtable_id table_spec);

void table_counter_init(void);
vtable_id table_counter_set(vtable_id counter_spec, vtable_id val);

#endif /* increment_table_id.h */
