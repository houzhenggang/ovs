#include <config.h>

#include "timeout_act.h"

#include "byte-order.h"
#include "dynamic-string.h"
#include "learn.h"
#include "learn_delete.h"
#include "match.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-parse.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "ofproto/ofproto-provider.h"
#include "openflow/openflow.h"
#include "unaligned.h"

enum ofperr timeout_act_check(const struct ofpact_timeout_act *act,
                              struct flow *flow, ofp_port_t max_ports,
                              uint8_t table_id, uint8_t n_tables,
                              enum ofputil_protocol *usable_protocols)
{
    // TODO - TEST
    if (act->ofpacts && act->ofpacts_len > 0) {
       return ofpacts_check(act->ofpacts, act->ofpacts_len, flow, max_ports,
                    table_id, n_tables, usable_protocols);
    }
    return 0; 
}

void timeout_act_format(const struct ofpact_timeout_act *act, struct ds *s)
{
    const struct ofpact *a;
    ds_put_cstr(s, "timeout_act(");

    OFPACT_FOR_EACH (a, act->ofpacts, act->ofpacts_len) {
        ofpact_format(a, s);
        ds_put_char(s, ',');
    }

    ds_put_char(s, ')');
}

static char * OVS_WARN_UNUSED_RESULT
timeout_act_parse__(char *orig, char *arg OVS_UNUSED, struct ofpbuf *ofpacts,
                    enum ofputil_protocol *usable_protocols) {
    /* -- ORIGINAL - Works, but error in check -- */
    struct ofpact_timeout_act *act;
    char *act_str = xstrdup(orig);

    struct ofpbuf timeout_ofpacts;
    char *error;
    unsigned int len;
 
    act = ofpact_put_TIMEOUT_ACT(ofpacts);
    
    ofpbuf_init(&timeout_ofpacts, 32);

    error = ofpacts_parse_instructions(act_str, &timeout_ofpacts,
         usable_protocols);
    if (error) {
        ofpbuf_uninit(&timeout_ofpacts);
        free(act_str);
        return error;
    }
    
    len = timeout_ofpacts.size;
    
    ofpbuf_put_zeros(ofpacts, len);
    
    act = ofpacts->header;
    act->ofpacts_len += len;

    act->ofpacts = ofpbuf_steal_data(&timeout_ofpacts);
    ofpact_update_len(ofpacts, &act->ofpact);
    

    free(act_str);
    return NULL;
}

char * OVS_WARN_UNUSED_RESULT
timeout_act_parse(char *arg, struct ofpbuf *ofpacts,
        enum ofputil_protocol *usable_protocols) {
    char *orig = xstrdup(arg);
    char *error = timeout_act_parse__(orig, arg, ofpacts, usable_protocols);
    free(orig);
    return error;
}
