# Contributions to Open vSwitch for Simon

## Porting progress

The following items need to be ported to this OVS version:

New actions
 - [x] increment_table_id
 - [x] learn_learn
 - [ ] learn_delete
 - [ ] Timeout actions

Pipeline/message changes
 - [ ] Automatic resubmit (enabling "parallelism" and "egress" support)
 - [ ] Egress matching for PACKET_INs
 - [ ] Ingress/egress register comparison
 - [ ] Other fixes as needed for proxy operation (which will become
   evident as above features are implemented)



## Table architecture 

The table space is now segmented as follows:

 Tables | Purpose
    --- | ---
  0-149 | Ingress
150-199 | Production
200-253 | Egress

Ingress and egress tables are evaluated using "automatic resubmit,"
meaning that the next table in the block will be evaluated so long as
the current table ID is less than the block's atomic counter value.

## Operation of egress tables

When a flow is being evaluated in the production tables and it reaches
a "terminal action," or an action that would normally signal the end
of evaluation (such as an output, flood, controller action, or a
"drop" action, which is the lack of an action), the flow is
resubmitted to the beginning of the egress table space.  In addition,
the intended output port is loaded into register 1 so that it can be
used in egress table matching.  If the terminal action was a flood,
drop, or controller action, the corresponding OpenFlow reserved port
number is loaded into register 1 instead (OFPP_FLOOD, OFPP_NONE, or
OFPP_CONTROLLER, respectively).  

In order to evaluate decisions made by the controller using a
PACKET_OUT message, the proxy generates a PACKET_OUT using a new OF
reserved prort OFPP_EGRESS, which is used to submit a flow directly to
the egress tables.  In order to easily pass the controller's output
port decision in this message (ie, using a stupid hack), the output
port number is stored in this message's XID field and loaded into
register 1 for processing.

## New Actions
### timeout_act
  Installing a rule with timeout_act creates a list of actions which are 
  only executing upon a rule timing out. 
  Syntax:
    timeout_act(..regular syntax for actions..)

### learn_delete
  Exact same syntax as the learn action, except a rule is deleted instead
  of being added.
  
  Example (run as root):
```
    ovs-vsctl add-br br0
    ovs-ofctl add-flow br0 "table=1, priority=5, eth_dst=11:11:11:11:11:11 actions=resubmit(,3)"
    ovs-ofctl add-flow br0 "table=0, priority=20, actions=learn_delete(table=1, NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]), resubmit(,2)"
    ovs-appctl ofproto/trace br0 dl_dst=20:20:20:20:20:20,eth_src=11:11:11:11:11:11 -generate
    ovs-ofctl dump-flows br0
```

### learn_learn
  The learn action which can install an arbitrary set of actions for the 
  learned rule.
  NOTE: Actions are enclosed within { }.
  Example:
```
    ovs-vsctl add-br br0
    ovs-ofctl add-flow br0 "table=2 action=learn_learn(table=10, NXM_OF_VLAN_TCI[0..11], actions={resubmit(,3)}), resubmit(,10)"
    ovs-appctl ofproto/trace br0 dl_dst=10:10:10:10:10:10,vlan_tci=0x3 -generate
    ovs-ofctl dump-flows br0
```

### increment_table_id:
  Increment a global atomic counter indicating the next ingress or
  egress table.
  NOTE: In order to use the counter value, use learn_learn's property
  use_atomic_table with the argument INGRESS or EGRESS.
  Example:
```
    ovs-vsctl add-br br0
    ovs-ofctl add-flow br0 "table=0 action=increment_table_id(INGRESS),learn_learn(table=10, use_atomic_table=INGRESS, NXM_OF_VLAN_TCI[0..11], NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]),learn_learn(table=11, use_atomic_cookie=1, NXM_OF_VLAN_TCI[0..11], NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[]),resubmit(,3)"
    ovs-appctl ofproto/trace br0 dl_src=10:10:10:10:10:10,vlan_tci=0x3 -generate
    ovs-ofctl dump-flows br0
```

## Register comparisons

In order to match against fields of the original flow in the egress
tables, fields of the original flow are loaded into predefined
registers during processing in the ingress tables.  When a flow begins
processing in the egress tables (that is, before it starts evaluation
in table 200), these values of these registers are compared to the
current flow fields.  If the comparison is a success, a 1 is stored in
the original register, otherwise, a zero is stored to the appropriate
output register.  In this way, we can achieve register matching by
matching on the result of the comparison in the egress tables.

### Register map

To perform comparisons, the input flow fields must be loaded into the
following registers.

#### Inputs

 Reg | Function
----:|----
  0  | `Match tag`
  1  | `Output status (output port)`
2-6  | `Unused`
  7  | `dl_type (2 bytes)`
  8  | `Bits 31-16: dl_src[47:32], Bits 15-0:  dl_dst[47-32] (See note)`
  9  | `dl_src[31:0]`
 10  | `dl_dst[31:0]`
 11  | `ip_proto (1 byte)`
 12  | `ip_src (4 bytes)`
 13  | `ip_dst (4 bytes)`
 14  | `tp_src (2 bytes)`
 15  | `tp_dst (2 bytes)`


Since the dl_src and dst_fields are larger than a single 32-bit
register, the upper two bytes of the source and destination fields are
loaded into the higher and lower two bytes of register 8,
respectively, while the remainder of each field is loaded into
registers 9 and 10, respectively.  Be sure to load the correct portion
of each field into the appropriate register.

After the comparisons are performed, the results of each comparison
are stored in the following registers.

#### Outputs

Reg  | Function
----:|----
  0  | `Match tag`
  1  | `Output status (output port)`
  2  | `p.dl_type  ==   p'.dl_type`
  3  | `p.dl_src   ==   p'.dl_src`
  4  | `p.dl_src   ==   p'.dl_dst`
  5  | `p.dl_dst   ==   p'.dl_src`
  6  | `p.dl_dst   ==   p'.dl_dst`
  7  | `p.ip_proto ==   p'.ip_proto`
  8  | `p.ip_src   ==   p'.ip_src`
  9  | `p.ip_src   ==   p'.ip_dst`
 10  | `p.ip_dst   ==   p'.ip_src`
 11  | `p.ip_dst   ==   p'.ip_dst`
 12  | `p.tp_src   ==   p'.tp_src`
 13  | `p.tp_src   ==   p'.tp_dst`
 14  | `p.tp_dst   ==   p'.tp_src`
 15  | `p.tp_dst   ==   p'.tp_dst`


Note: Since there is no definitive way to know which fields have been
loaded, all comparisons are always performed regardless of the input
are overwritten when a flow is submitted to the egress tables.  

### Example

An example rule that loads all fields supported for comparison is as
follows:
```
1 sudo ovs-ofctl add-flow s1 "table=0,ip,tcp,actions= \
2   move:NXM_OF_ETH_TYPE[]->NXM_NX_REG7[0..15], \
3   move:NXM_OF_ETH_SRC[32..47]->NXM_NX_REG8[16..31],move:NXM_OF_ETH_SRC[0..31]->NXM_NX_REG9[],\
4   move:NXM_OF_ETH_DST[32..47]->NXM_NX_REG8[0..15],move:NXM_OF_ETH_DST[0..31]->NXM_NX_REG10[0..31],\
5   move:NXM_OF_IP_PROTO[]->NXM_NX_REG11[0..7], \
6   move:NXM_OF_IP_SRC[]->NXM_NX_REG12[], \
7   move:NXM_OF_IP_DST[]->NXM_NX_REG13[], \
8   move:NXM_OF_TCP_SRC[]->NXM_NX_REG14[0..15], \
9   move:NXM_OF_TCP_DST[]->NXM_NX_REG15[0..15]"
```

This rule can be matched as follows:
```
sudo ovs-ofctl add-flow s1 "table=200,reg2=0x1,reg3=0x1,reg6=0x1, \
 			    reg7=0x1,reg8=0x1,reg11=0x1, \
			    reg12=0x1,reg15=0x1, \
		            actions=output:3"
```