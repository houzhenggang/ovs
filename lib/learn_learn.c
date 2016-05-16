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

#include "learn_learn.h"

#include "byte-order.h"
#include "dynamic-string.h"
#include <inttypes.h>
#include "match.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-parse.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "unaligned.h"
#include <unistd.h>

#include "increment_table_id.h"

void
change_spec_values(struct ofpact_learn_spec *start,
		   struct ofpact_learn_spec *end,
		   const struct flow *flow);


static char *
get_matching_bracket(char *str) {
    char *instance;
    int count;
    count = 0;

    instance = str;

    while (*instance != '\0') {
	if (*instance == '{') {
	    count++;
	} else if (*instance == '}') {
	    count--;
	    if (count == 0) {
		return instance;
	    }
	}
	instance++;
    }

    return NULL;
}


void
change_spec_values(struct ofpact_learn_spec *start,
		   struct ofpact_learn_spec *end,
		   const struct flow *flow) {

    struct ofpact_learn_spec *spec;

    for (spec = start; spec < end; spec++) {
	// TODO TEST
	if (spec->defer_count == 0xff) {
	    continue;
	} else if (spec->defer_count >= 1) {
	    spec->defer_count--;
	} else {
	    // Parse value into an mf_value
	    const struct mf_field *dst;
	    union mf_value imm;

	    dst = spec->src.field;
	    mf_get_value(dst, flow, &imm);

	    // Memset & memcpy value into spec->src_imm
	    memset(&spec->src_imm, 0, sizeof spec->src_imm);
	    memcpy(&spec->src_imm.u8[sizeof spec->src_imm - dst->n_bytes],
		   &imm, dst->n_bytes);

	    spec->n_bits = spec->src.n_bits;

	    // Update the spec's src_type
	    spec->src_type = NX_LEARN_SRC_IMMEDIATE;
	    spec->defer_count = 0xff;
	  }
    }
}

void
populate_deferral_values(struct ofpact_learn_learn *learn,
			 const struct flow *flow) {
    struct ofpact_learn_spec *spec;
    struct ofpact_learn_spec *end;
    struct ofpact *learn_actions;

    spec = (struct ofpact_learn_spec *) learn->data;
    end = &spec[learn->n_specs];

     change_spec_values(spec, end, flow);

     // Recursively call do_deferral on nested actions
     learn_actions = (struct ofpact *) end;

     do_deferral(learn_actions, learn->ofpacts_len, flow);
 }

void do_deferral(struct ofpact *ofpacts, uint32_t ofpacts_len,
		 const struct flow *flow) {
    struct ofpact *a;

    OFPACT_FOR_EACH(a, ofpacts, ofpacts_len) {
	if (a->type == OFPACT_LEARN_LEARN) {
	    populate_deferral_values(ofpact_get_LEARN_LEARN(a), flow);
	}
// TODO:  Test after adding support for learn_delete
#ifdef OFPACT_LEARN_DELETE
	else if (a->type == OFPACT_LEARN_DELETE) {
	    struct ofpact_learn_delete *del;

	    del = ofpact_get_LEARN_DELETE(a);
	    change_spec_values(del->specs, &del->specs[del->n_specs], flow);
	}
#endif
    }
}


/* Checks that 'learn' is a valid action on 'flow'.  Returns 0 if it is valid,
 * otherwise an OFPERR_*. */
enum ofperr
learn_learn_check(const struct ofpact_learn_learn * learn,
		  struct flow * flow, ofp_port_t max_ports,
		  uint8_t table_id, uint8_t n_tables,
		  enum ofputil_protocol *usable_protocols)
{
    const struct ofpact_learn_spec *spec;
    const struct ofpact_learn_spec *spec_end;
    struct match match;
    struct ofpact *ofpacts;

    match_init_catchall(&match);
    spec = (const struct ofpact_learn_spec *) learn->data;
    spec_end = &spec[learn->n_specs];

    for (spec = (const struct ofpact_learn_spec *) learn->data;
	 spec < spec_end; spec++) {
	enum ofperr error;

	/* Check the source. */
	if (spec->src_type == NX_LEARN_SRC_FIELD) {
	    error = mf_check_src(&spec->src, flow);
	    if (error) {
		return error;
	    }
	}

	/* Check the destination. */
	switch (spec->dst_type) {
	case NX_LEARN_DST_MATCH:
	    error = mf_check_src(&spec->dst, &match.flow);
	    if (error) {
		return error;
	    }

	    mf_write_subfield(&spec->dst, &spec->src_imm, &match);
	    break;

	case NX_LEARN_DST_LOAD:
	    error = mf_check_dst(&spec->dst, &match.flow);
	    if (error) {
		fprintf(stderr, "thoff: learn_check err3\n");
		return error;
	    }
	    break;

	case NX_LEARN_DST_OUTPUT:
	    /* Nothing to do. */
	    break;

	case NX_LEARN_DST_RESERVED:
	    /* Addition for resubmit */
	    break;
	}
    }

    // TODO Check actions
    ofpacts = (struct ofpact *) spec_end;
    if (ofpacts && learn->ofpacts_len > 0) {
	return ofpacts_check(ofpacts, learn->ofpacts_len, flow,
			     max_ports, table_id, n_tables, usable_protocols);
    }

    return 0;
}

/* Composes 'fm' so that executing it will implement 'learn' given that the
 * packet being processed has 'flow' as its flow.
 *
 * Uses 'ofpacts' to store the flow mod's actions.  The caller must initialize
 * 'ofpacts' and retains ownership of it.  'fm->ofpacts' will point into the
 * 'ofpacts' buffer.
 *
 * The caller has to actually execute 'fm'. */
void
learn_learn_execute(const struct ofpact_learn_learn *learn,
		    const struct flow *flow, struct ofputil_flow_mod *fm,
		    struct ofpbuf *ofpacts, uint8_t rule_table,
		    struct vtable_ctx *vtable_ctx)
{
    const struct ofpact_learn_spec *spec;
    const struct ofpact_learn_spec *end;

    vtable_id vtable_id;

    spec = (const struct ofpact_learn_spec *) learn->data;
    end = &spec[learn->n_specs];

    match_init_catchall(&fm->match);
    fm->priority = learn->priority;
    fm->cookie = htonll(0);
    fm->cookie_mask = htonll(0);
    fm->new_cookie = htonll(learn->cookie);

    if (learn->table_spec == LEARN_USING_INGRESS_ATOMIC_TABLE) {
	fm->table_id = learn->table_id;
    } else if (learn->table_spec == LEARN_USING_EGRESS_ATOMIC_TABLE) {
	fm->table_id = learn->table_id;
    } else if (learn->table_spec == LEARN_USING_RULE_TABLE) {
	fm->table_id = rule_table;
    } else {
	fm->table_id = learn->table_id;
    }

    fm->modify_cookie = fm->new_cookie != htonll(UINT64_MAX);
    fm->command = OFPFC_MODIFY_STRICT;
    fm->idle_timeout = learn->idle_timeout;
    fm->hard_timeout = learn->hard_timeout;
    fm->importance = 0;
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_NONE;
    fm->flags = learn->flags;
    fm->ofpacts = NULL;
    fm->ofpacts_len = 0;

    if (learn->fin_idle_timeout || learn->fin_hard_timeout) {
	struct ofpact_fin_timeout *oft;

	oft = ofpact_put_FIN_TIMEOUT(ofpacts);
	oft->fin_idle_timeout = learn->fin_idle_timeout;
	oft->fin_hard_timeout = learn->fin_hard_timeout;
    }

    // Set the metadata field in the match based on the atomic ID
    if (learn->table_spec == LEARN_USING_INGRESS_ATOMIC_TABLE) {
	ovs_assert(vtable_ctx->ingress_set);
	vtable_id = vtable_ctx->ingress_id;

	match_set_metadata(&fm->match, htonll(vtable_id));
    } else if (learn->table_spec == LEARN_USING_EGRESS_ATOMIC_TABLE) {
	ovs_assert(vtable_ctx->egress_set);
	vtable_id = vtable_ctx->egress_id;

	match_set_metadata(&fm->match, htonll(vtable_id));
    }

    for (spec = (const struct ofpact_learn_spec *) learn->data; spec < end; spec++) {
	struct ofpact_set_field *sf;
	union mf_subvalue value;
	//int chunk, ofs;

	if (spec->src_type == NX_LEARN_SRC_FIELD) {
	    mf_read_subfield(&spec->src, flow, &value);
	} else {
	    value = spec->src_imm;
	}

	switch (spec->dst_type) {
	case NX_LEARN_DST_MATCH:
	    mf_write_subfield(&spec->dst, &value, &fm->match);
	    break;

	case NX_LEARN_DST_LOAD:
// TODO:  This was removed in place of the below solution,
// need to test to confirm.
#if 0
	    for (ofs = 0; ofs < spec->n_bits; ofs += chunk) {
		struct ofpact_reg_load *load;

		chunk = MIN(spec->n_bits - ofs, 64);

		load = ofpact_put_REG_LOAD(ofpacts);
		load->dst.field = spec->dst.field;
		load->dst.ofs = spec->dst.ofs + ofs;
		load->dst.n_bits = chunk;
		bitwise_copy(&value, sizeof value, ofs,
			     &load->subvalue, sizeof load->subvalue, 0,
			     chunk);
	    }
#endif
	    sf = ofpact_put_reg_load(ofpacts);
	    sf->field = spec->dst.field;
	    bitwise_copy(&value, sizeof value, 0,
			 &sf->value, spec->dst.field->n_bytes, spec->dst.ofs,
			 spec->n_bits);
	    bitwise_one(&sf->mask, spec->dst.field->n_bytes, spec->dst.ofs,
			spec->n_bits);
	    break;

	    break;

	case NX_LEARN_DST_OUTPUT:
	    if (spec->n_bits <= 16
		|| is_all_zeros(value.u8, sizeof value - 2)) {
		ofp_port_t port = u16_to_ofp(ntohs(value.be16[7]));

		if (ofp_to_u16(port) < ofp_to_u16(OFPP_MAX)
		    || port == OFPP_IN_PORT
		    || port == OFPP_FLOOD
		    || port == OFPP_LOCAL
		    || port == OFPP_ALL) {
		    ofpact_put_OUTPUT(ofpacts)->port = port;
		}
	    }
	    break;
#if 0 // Removed since this was added by FAST, but we don't use it.
	case NX_LEARN_DST_RESERVED:
	    resubmit = ofpact_put_RESUBMIT(ofpacts);
	    resubmit->ofpact.compat = OFPUTIL_NXAST_RESUBMIT_TABLE;
	    /* hard coded values */
	    resubmit->table_id = 2;
	    break;
#endif
	}
    }

    struct ofpact *learn_actions;
    learn_actions = (struct ofpact *) end;

    // TODO - Do a copy of the data, in learn_actions
    struct ofpact *copied_learn_actions;
    copied_learn_actions = xmalloc(learn->ofpacts_len);
    copied_learn_actions = memcpy(copied_learn_actions,
				  learn_actions, learn->ofpacts_len);

    // Do spec substitution as needed
    do_deferral(copied_learn_actions, learn->ofpacts_len, flow);

    ofpbuf_put(ofpacts, copied_learn_actions, learn->ofpacts_len);

    ofpact_pad(ofpacts);

    fm->ofpacts = ofpacts->data;
    fm->ofpacts_len = ofpacts->size;

    free(copied_learn_actions);
}


/* Perform a bitwise-OR on 'wc''s fields that are relevant as sources in
 * the learn action 'learn'. */
void
learn_learn_mask(const struct ofpact_learn_learn *learn,
		 struct flow_wildcards *wc)
{
    const struct ofpact_learn_spec *spec;
    const struct ofpact_learn_spec *spec_end;
    union mf_subvalue value;

    spec = (const struct ofpact_learn_spec *) learn->data;
    spec_end = spec + learn->n_specs;

    memset(&value, 0xff, sizeof value);
    for (spec = (const struct ofpact_learn_spec *) learn->data;
	 spec < spec_end; spec++) {
	if (spec->src_type == NX_LEARN_SRC_FIELD) {
	    mf_write_subfield_flow(&spec->src, &value, &wc->masks);
	}
    }
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_learn_parse_load_immediate(const char *s, struct ofpact_learn_spec *spec)
{
    const char *full_s = s;
    const char *arrow = strstr(s, "->");
    struct mf_subfield dst;
    union mf_subvalue imm;
    char *error;

    memset(&imm, 0, sizeof imm);
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && arrow) {
	const char *in = arrow - 1;
	uint8_t *out = imm.u8 + sizeof imm.u8 - 1;
	int n = arrow - (s + 2);
	int i;

	for (i = 0; i < n; i++) {
	    int hexit = hexit_value(in[-i]);
	    if (hexit < 0) {
		return xasprintf("%s: bad hex digit in value", full_s);
	    }
	    out[-(i / 2)] |= i % 2 ? hexit << 4 : hexit;
	}
	s = arrow;
    } else {
	imm.be64[1] = htonll(strtoull(s, (char **) &s, 0));
    }

    if (strncmp(s, "->", 2)) {
	return xasprintf("%s: missing `->' following value", full_s);
    }
    s += 2;

    error = mf_parse_subfield(&dst, s);
    if (error) {
	return error;
    }

    if (!bitwise_is_all_zeros(&imm, sizeof imm, dst.n_bits,
			      (8 * sizeof imm) - dst.n_bits)) {
	return xasprintf("%s: value does not fit into %u bits",
			 full_s, dst.n_bits);
    }

    spec->n_bits = dst.n_bits;
    spec->src_type = NX_LEARN_SRC_IMMEDIATE;
    spec->src_imm = imm;
    spec->dst_type = NX_LEARN_DST_LOAD;
    spec->dst = dst;
    return NULL;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_learn_parse_spec(const char *orig, char *name, char *value,
		       struct ofpact_learn_spec *spec)
{
    // TODO - Need to modify to add some form of parsing!

    if (mf_from_name(name)) {
	const struct mf_field *dst = mf_from_name(name);
	union mf_value imm;
	char *error;

	error = mf_parse_value(dst, value, &imm);
	if (error) {
	    return error;
	}

	spec->n_bits = dst->n_bits;
	spec->src_type = NX_LEARN_SRC_IMMEDIATE;
	memset(&spec->src_imm, 0, sizeof spec->src_imm);
	memcpy(&spec->src_imm.u8[sizeof spec->src_imm - dst->n_bytes],
	       &imm, dst->n_bytes);
	spec->dst_type = NX_LEARN_DST_MATCH;
	spec->dst.field = dst;
	spec->dst.ofs = 0;
	spec->dst.n_bits = dst->n_bits;
    } else if (strchr(name, '[')) {
	/* Parse destination and check prerequisites. */
	char *error;

	error = mf_parse_subfield(&spec->dst, name);
	if (error) {
	    return error;
	}

	/* Parse source and check prerequisites. */
	if (value[0] != '\0') {
	    error = mf_parse_subfield(&spec->src, value);
	    if (error) {
		return error;
	    }
	    if (spec->src.n_bits != spec->dst.n_bits) {
		return xasprintf("%s: bit widths of %s (%u) and %s (%u) "
				 "differ", orig, name, spec->src.n_bits, value,
				 spec->dst.n_bits);
	    }
	} else {
	    spec->src = spec->dst;
	}

	spec->n_bits = spec->src.n_bits;
	spec->src_type = NX_LEARN_SRC_FIELD;
	spec->dst_type = NX_LEARN_DST_MATCH;
    } else if (!strcmp(name, "load")) {
	if (value[strcspn(value, "[-")] == '-') {
	    char *error = learn_learn_parse_load_immediate(value, spec);
	    if (error) {
		return error;
	    }
	} else {
	    struct ofpact_reg_move move;
	    char *error;

	    error = nxm_parse_reg_move(&move, value);
	    if (error) {
		return error;
	    }

	    spec->n_bits = move.src.n_bits;
	    spec->src_type = NX_LEARN_SRC_FIELD;
	    spec->src = move.src;
	    spec->dst_type = NX_LEARN_DST_LOAD;
	    spec->dst = move.dst;
	}
    } else if (!strcmp(name, "output")) {
	char *error = mf_parse_subfield(&spec->src, value);
	if (error) {
	    return error;
	}

	spec->n_bits = spec->src.n_bits;
	spec->src_type = NX_LEARN_SRC_FIELD;
	spec->dst_type = NX_LEARN_DST_OUTPUT;
    } else if (!strcmp(name, "reserved")) {
	char *error = mf_parse_subfield(&spec->src, value);
	if (error) {
	    return error;
	}

	spec->n_bits = spec->src.n_bits;
	spec->src_type = NX_LEARN_SRC_FIELD;
	spec->dst_type = NX_LEARN_DST_RESERVED;
    } else {
	return xasprintf("%s: unknown keyword %s", orig, name);
    }

    return NULL;
}

/* Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
static char * OVS_WARN_UNUSED_RESULT
learn_learn_parse__(char *orig, char *arg, struct ofpbuf *ofpacts,
		    enum ofputil_protocol *usable_protocols)
{
    struct ofpact_learn_learn *learn;
    struct match match;
    char *name, *value;
    char *error;
    char *act_str;
    char *end_act_str;
    struct ofpbuf learn_ofpacts_buf;

    act_str = strstr(orig, "actions");
    end_act_str = NULL;
    if (act_str) {
	act_str = strchr(act_str + 1, '=');
	if (!act_str) {
	    return xstrdup("Must specify action");
	}

	act_str = strchr(act_str, '{');
	if (!act_str) {
	    return xstrdup("learn_learn requires actions to be bound by '{...}'");
	}
	end_act_str = get_matching_bracket(act_str);

	act_str = act_str + 1;

	if (!end_act_str) {
	    return xstrdup("learn_learn requires actions to be bound by '{...}' 2}");
	}
    }


    ofpbuf_init(&learn_ofpacts_buf, 32);

    learn = ofpact_put_LEARN_LEARN(ofpacts);

    learn->idle_timeout = OFP_FLOW_PERMANENT;
    learn->hard_timeout = OFP_FLOW_PERMANENT;
    learn->priority = OFP_DEFAULT_PRIORITY;
    learn->table_id = 1;

    match_init_catchall(&match);
    while (ofputil_parse_key_value(&arg, &name, &value)) {
	if (!strcmp(name, "table")) {
	    learn->table_id = atoi(value);
	    if (learn->table_id == 255) {
		return xasprintf("%s: table id 255 not valid for `learn' "
				 "action", orig);
	    }
	} else if (!strcmp(name, "priority")) {
	    learn->priority = atoi(value);
	} else if (!strcmp(name, "idle_timeout")) {
	    learn->idle_timeout = atoi(value);
	} else if (!strcmp(name, "hard_timeout")) {
	    learn->hard_timeout = atoi(value);
	} else if (!strcmp(name, "fin_idle_timeout")) {
	    learn->fin_idle_timeout = atoi(value);
	} else if (!strcmp(name, "fin_hard_timeout")) {
	    learn->fin_hard_timeout = atoi(value);
	} else if (!strcmp(name, "cookie")) {
	    learn->cookie = strtoull(value, NULL, 0);
	} else if (!strcmp(name, "learn_on_timeout")) {
	    learn->learn_on_timeout = atoi(value);
	} else if (!strcmp(name, "use_atomic_table")) {
	    if(!strcmp(value, "INGRESS")) {
		learn->table_spec = LEARN_USING_INGRESS_ATOMIC_TABLE;
	    } else if(!strcmp(value, "EGRESS")) {
		learn->table_spec = LEARN_USING_EGRESS_ATOMIC_TABLE;
	    } else {
		return xasprintf("%s: Invalid counter spec, must be 'INGRESS' or 'EGRESS'", orig);
	    }
	} else if (!strcmp(name, "use_rule_table")) {
	    if (atoi(value) != 0) {
		learn->table_spec = LEARN_USING_RULE_TABLE;
	    }
	} else if (!strcmp(name, "actions")) {
	    size_t len = ofpacts->size;
	    char all_actions[end_act_str - act_str + 1];
	    void *actions;

	    memcpy(all_actions, act_str, end_act_str - act_str);
	    all_actions[end_act_str - act_str] = '\0';

	    error = ofpacts_parse_instructions(all_actions, &learn_ofpacts_buf,
					       usable_protocols);
	    if (error) {
		ofpbuf_uninit(&learn_ofpacts_buf);
		return error;
	    }

	    actions = ofpbuf_put_zeros(ofpacts, learn_ofpacts_buf.size);

	    learn = ofpacts->header;
	    learn->ofpacts_len += ofpacts->size - len;
	    memcpy(actions, learn_ofpacts_buf.data, learn_ofpacts_buf.size);

	    break;
	} else {
	    uint8_t deferral_count;
	    struct ofpact_learn_spec *spec;
	    char *error;
	    char *defer_str;

	    deferral_count = 0xff;

	    spec = ofpbuf_put_zeros(ofpacts, sizeof *spec);
	    learn = ofpacts->header;
	    learn->n_specs++;

	    defer_str = strstr(value, "(defer");

	    if (!defer_str) {
		error = learn_learn_parse_spec(orig, name, value, spec);
	    } else {
		int deferral_err;
		char val_str[defer_str - value + 1];

		deferral_err = sscanf(strstr(value, "(defer"),
				      "(defer=%" SCNu8 ")",
				      &deferral_count);
		if (deferral_err == 0) {
		    return xstrdup("deferral syntax: (defer=#)");
		}


		memcpy(val_str, value, defer_str - value);
		val_str[defer_str - value] = '\0';

		error = learn_learn_parse_spec(orig, name, val_str, spec);
	    }

	    if (error) {
		return error;
	    }

	    // Attach deferral count
	    spec->defer_count = deferral_count;

	    /* Update 'match' to allow for satisfying destination
	     * prerequisites. */
	    if (spec->src_type == NX_LEARN_SRC_IMMEDIATE
		&& spec->dst_type == NX_LEARN_DST_MATCH) {
		mf_write_subfield(&spec->dst, &spec->src_imm, &match);
	    }
	}
    }

    ofpact_update_len(ofpacts, &learn->ofpact);

    return NULL;
}

/* Parses 'arg' as a set of arguments to the "learn" action and appends a
 * matching OFPACT_LEARN action to 'ofpacts'.  ovs-ofctl(8) describes the
 * format parsed.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.
 *
 * If 'flow' is nonnull, then it should be the flow from a struct match that is
 * the matching rule for the learning action.  This helps to better validate
 * the action's arguments.
 *
 * Modifies 'arg'. */
char * OVS_WARN_UNUSED_RESULT
learn_learn_parse(char *arg, struct ofpbuf *ofpacts,
		  enum ofputil_protocol *usable_protocols)
{
    char *orig = xstrdup(arg);
    char *error = learn_learn_parse__(orig, arg, ofpacts, usable_protocols);
    free(orig);
    return error;
}

/* Appends a description of 'learn' to 's', in the format that ovs-ofctl(8)
 * describes. */
void
learn_learn_format(const struct ofpact_learn_learn *learn, struct ds *s)
{
    const struct ofpact_learn_spec *spec;
    const struct ofpact_learn_spec *spec_end;
    struct match match;

    struct ofpact *ofpacts;
    const struct ofpact *a;

    match_init_catchall(&match);

    ds_put_format(s, "learn_learn(table=%"PRIu8, learn->table_id);
    if (learn->idle_timeout != OFP_FLOW_PERMANENT) {
	ds_put_format(s, ",idle_timeout=%"PRIu16, learn->idle_timeout);
    }
    if (learn->hard_timeout != OFP_FLOW_PERMANENT) {
	ds_put_format(s, ",hard_timeout=%"PRIu16, learn->hard_timeout);
    }
    if (learn->fin_idle_timeout) {
	ds_put_format(s, ",fin_idle_timeout=%"PRIu16, learn->fin_idle_timeout);
    }
    if (learn->fin_hard_timeout) {
	ds_put_format(s, ",fin_hard_timeout=%"PRIu16, learn->fin_hard_timeout);
    }
    if (learn->priority != OFP_DEFAULT_PRIORITY) {
	ds_put_format(s, ",priority=%"PRIu16, learn->priority);
    }
    if (learn->flags & OFPFF_SEND_FLOW_REM) {
	ds_put_cstr(s, ",OFPFF_SEND_FLOW_REM");
    }
    if (learn->cookie != 0) {
	ds_put_format(s, ",cookie=%#"PRIx64, learn->cookie);
    }

    if (learn->table_spec == LEARN_USING_INGRESS_ATOMIC_TABLE) {
	ds_put_cstr(s, ",table_spec=LEARN_USING_INGRESS_ATOMIC_TABLE");
    } else if (learn->table_spec == LEARN_USING_EGRESS_ATOMIC_TABLE) {
	ds_put_cstr(s, ",table_spec=LEARN_USING_EGRESS_ATOMIC_TABLE");
    } else if (learn->table_spec == LEARN_USING_RULE_TABLE) {
	ds_put_cstr(s, ",table_spec=LEARN_USING_RULE_TABLE");
    }

    spec = (const struct ofpact_learn_spec *) learn->data;
    spec_end = spec + learn->n_specs;

    for (spec = (const struct ofpact_learn_spec *) learn->data;
	 spec < spec_end; spec++) {
	ds_put_char(s, ',');

	switch (spec->src_type | spec->dst_type) {
	case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_MATCH:
	    if (spec->dst.ofs == 0
		&& spec->dst.n_bits == spec->dst.field->n_bits) {
		union mf_value value;

		memset(&value, 0, sizeof value);
		bitwise_copy(&spec->src_imm, sizeof spec->src_imm, 0,
			     &value, spec->dst.field->n_bytes, 0,
			     spec->dst.field->n_bits);
		ds_put_format(s, "%s=", spec->dst.field->name);
		mf_format(spec->dst.field, &value, NULL, s);
	    } else {
		mf_format_subfield(&spec->dst, s);
		ds_put_char(s, '=');
		mf_format_subvalue(&spec->src_imm, s);
	    }



	    break;

	case NX_LEARN_SRC_FIELD | NX_LEARN_DST_MATCH:
	    mf_format_subfield(&spec->dst, s);
	    if (spec->src.field != spec->dst.field ||
		spec->src.ofs != spec->dst.ofs) {
		ds_put_char(s, '=');
		mf_format_subfield(&spec->src, s);
	    }
	    break;

	case NX_LEARN_SRC_IMMEDIATE | NX_LEARN_DST_LOAD:
	    ds_put_format(s, "load:");
	    mf_format_subvalue(&spec->src_imm, s);
	    ds_put_cstr(s, "->");
	    mf_format_subfield(&spec->dst, s);
	    break;

	case NX_LEARN_SRC_FIELD | NX_LEARN_DST_LOAD:
	    ds_put_cstr(s, "load:");
	    mf_format_subfield(&spec->src, s);
	    ds_put_cstr(s, "->");
	    mf_format_subfield(&spec->dst, s);
	    break;

	case NX_LEARN_SRC_FIELD | NX_LEARN_DST_OUTPUT:
	    ds_put_cstr(s, "output:");
	    mf_format_subfield(&spec->src, s);
	    break;

	case NX_LEARN_SRC_FIELD | NX_LEARN_DST_RESERVED:
	    ds_put_cstr(s, "reserved:");
	    mf_format_subfield(&spec->src, s);
	    break;

	}
	if (spec->defer_count < 0xff) {
	    ds_put_format(s, "(defer=%" PRIu8 ")", spec->defer_count);
	}
    }
    ds_put_cstr(s, ",actions=");

    // Add actions
    ofpacts = (struct ofpact *) spec_end;

    OFPACT_FOR_EACH (a, ofpacts, learn->ofpacts_len) {
	ofpact_format(a, s);
	ds_put_char(s, ',');
    }
    ds_put_char(s, ')');
}
