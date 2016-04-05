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

#include <config.h>

#include "increment_table_id.h"

#include "byte-order.h"
#include "dynamic-string.h"
#include "match.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "unaligned.h"
#include <unistd.h>
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(increment_table_id);

/* Atomic type for our table IDs */
typedef atomic_ullong atomic_vtable_id;

BUILD_ASSERT_DECL(sizeof(atomic_ullong) == sizeof(ovs_be64));
BUILD_ASSERT_DECL(sizeof(vtable_id) == sizeof(atomic_vtable_id));

static atomic_vtable_id atomic_table_id_ingress = ATOMIC_VAR_INIT(0);
static atomic_vtable_id atomic_table_id_egress  = ATOMIC_VAR_INIT(0);

vtable_id increment_table_counter(vtable_id counter_spec, vtable_id inc);

/* Checks that 'incr_table_id' is a valid action on 'flow'.  Returns 0 always. */
enum ofperr
increment_table_id_check(const struct ofpact_increment_table_id *incr_table_id)
{
    struct match match;

    if((incr_table_id->counter_spec != TABLE_SPEC_INGRESS) &&
       (incr_table_id->counter_spec != TABLE_SPEC_EGRESS)) {
	return OFPERR_OFPBAC_BAD_SET_TYPE;
    }
    match_init_catchall(&match);

    return 0;
}

vtable_id
increment_table_counter(vtable_id counter_spec, vtable_id inc)
{
    vtable_id orig = 0;

    switch(counter_spec)
    {
    case TABLE_SPEC_INGRESS:
	atomic_add(&atomic_table_id_ingress, inc, &orig);

	if(inc != 0) {
	    VLOG_DBG("Incrementing ingress table id from:  %"PRIvtable ", inc:  %"PRIvtable, orig, inc);
	}

	if((inc != 0) && (orig != 0) && ((orig % SIMON_TABLE_INC_WARN_INTERVAL) == 0)) {
	    VLOG_WARN("Used %"PRIvtable" of %"PRIvtable" ingress tables",
		      orig, ((vtable_id)SIMON_TABLE_PRODUCTION_START));
	}

	break;
    case TABLE_SPEC_EGRESS:
	atomic_add(&atomic_table_id_egress, inc, &orig);

	if(inc != 0) {
	    VLOG_DBG("Incrementing egress table id from:  %"PRIvtable ", inc:  %"PRIvtable, orig, inc);
	}

	if((inc != 0) && (orig != 0) && ((orig % SIMON_TABLE_INC_WARN_INTERVAL) == 0)) {
	    VLOG_WARN("Used %"PRIvtable" of %"PRIvtable" egress tables",
		      orig, (vtable_id)(SIMON_TABLE_RESERVED_START - SIMON_TABLE_EGRESS_START));
	}

	break;
    default:
	VLOG_WARN("Unknown counter spec");
    }

    return orig;
}


/* Increments a global shared value for a table_id, and then returns the value */
vtable_id
increment_table_id_execute(const struct ofpact_increment_table_id *incr_table_id)
{
    vtable_id orig;

    // Increment table_id value
    //unsigned long long int orig;
    //atomic_add(&atomic_table, 1, &orig);
    orig = increment_table_counter(incr_table_id->counter_spec, 1);

    return orig;
}

vtable_id get_table_counter_by_id(vtable_id table_id)
{
    vtable_id counter_val = 0;
    if(TABLE_IS_INGRESS(table_id)) {
	counter_val = increment_table_counter(TABLE_SPEC_INGRESS, 0);

	//ovs_assert(counter_val < SIMON_TABLE_PRODUCTION_START);
    } else if(TABLE_IS_EGRESS(table_id)) {
	counter_val = increment_table_counter(TABLE_SPEC_EGRESS, 0);

	//ovs_assert(counter_val < SIMON_TABLE_RESERVED_START);
    } else {
	VLOG_WARN("Attempting to get counter table id with unknown spec:  %"PRIvtable, table_id);
    }

    return counter_val;
}

vtable_id get_table_counter_by_spec(vtable_id table_spec)
{
    vtable_id val =  increment_table_counter(table_spec, 0);
    //ovs_assert(val < (table_spec == TABLE_SPEC_INGRESS ? SIMON_TABLE_PRODUCTION_START : SIMON_TABLE_RESERVED_START));

    return val;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char *
increment_table_id_parse__(char *orig, char *arg, struct ofpbuf *ofpacts)
{
    struct ofpact_increment_table_id *incr_table_id;

    incr_table_id = ofpact_put_INCREMENT_TABLE_ID(ofpacts);

    incr_table_id->counter_spec = TABLE_SPEC_INGRESS;

    if(!strcmp(arg, "INGRESS")) {
	incr_table_id->counter_spec = TABLE_SPEC_INGRESS;
    } else if(!strcmp(arg, "EGRESS")) {
	incr_table_id->counter_spec = TABLE_SPEC_EGRESS;
    } else {
	return xasprintf("%s:  Invalid counter spec, must be 'INGRESS' or 'EGRESS'", orig);
    }

    return NULL;
}

/* Parses 'arg' as a set of arguments to the "increment_table_id" action and
 * appends a matching OFPACT_INCREMENT_TABLE_ID action to 'ofpacts'.
 * ovs-ofctl(8) describes the format parsed.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 *
 * If 'flow' is nonnull, then it should be the flow from a struct match that is
 * the matching rule for the learning action.  This helps to better validate
 * the action's arguments.
 *
 * Modifies 'arg'. */
char *
increment_table_id_parse(char *arg, struct ofpbuf *ofpacts)
{
    char *orig = xstrdup(arg);
    char *error = increment_table_id_parse__(orig, arg, ofpacts);
    free(orig);
    return error;
}

/* Appends a description of 'increment_table_id' to 's',
 * in the format that ovs-ofctl(8) describes. */
void
increment_table_id_format(const struct ofpact_increment_table_id *incr_table_id,
			  struct ds *s)
{
    struct match match;
    match_init_catchall(&match);

    ds_put_format(s, "increment_table_id(%s)",
		  (incr_table_id->counter_spec == TABLE_SPEC_EGRESS) ? "EGRESS" : "INGRESS");
}
