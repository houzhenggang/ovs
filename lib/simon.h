#ifndef SIMON_H
#define SIMON_H 1

#include "openflow/openflow-1.0.h"

// Table processing stages
#define SIMON_TABLE_INGRESS_START (0)
#define SIMON_TABLE_PRODUCTION_START (150)
#define SIMON_TABLE_EGRESS_START (200)
#define SIMON_TABLE_RESERVED_START (254) // Last table is reserved for OVS

#define SIMON_TABLE_INC_WARN_INTERVAL (20) // Warn on usage of every N tables

// Convenience macros for identifying table ranges
/* #define TABLE_IS_INGRESS(id) ((id >= SIMON_TABLE_INGRESS_START) && \ */
/* 			      (id < SIMON_TABLE_PRODUCTION_START)) */
#define TABLE_IS_INGRESS(id) ((id < SIMON_TABLE_PRODUCTION_START))

#define TABLE_IS_PRODUCTION(id) ((id >= SIMON_TABLE_PRODUCTION_START) && \
				 (id < SIMON_TABLE_EGRESS_START))

#define TABLE_IS_EGRESS(id) ((id >= SIMON_TABLE_EGRESS_START) && \
			     (id < 254))


#define SIMON_USE_OF_OUTPUT_EGRESS 1

// Register definitions
#define SIMON_OUTPUT_STATUS_REG (1)

#define SIMON_OUTPUT_STATUS_FLOOD      (OFPP_FLOOD)
#define SIMON_OUTPUT_STATUS_CONTROLLER (OFPP_CONTROLLER)
#define SIMON_OUTPUT_STATUS_DROP       (OFPP_NONE)


#define SIMON_OFP_IN_XID_MASK          (0xbe000000)

// Register compare map

/** INPUT REGISTERS **/
#define SIMON_REG_IDX_DL_TYPE    (7)
#define SIMON_REG_IDX_DL_SRC_HI  (8) /* Input:  bits 47-32 of dl_src, stored in upper two bytes of register. */
#define SIMON_REG_IDX_DL_DST_HI  (8) /* Input:  bits 47-32 of dl_dst, stored in lower two bytes of register. */
#define SIMON_REG_IDX_DL_SRC     (9) /* Input:  bits 31-0  of dl_src, compare result for dl_src stored here on output. */
#define SIMON_REG_IDX_DL_DST    (10) /* Input:  bits 31-0  of dl_dst, compare result for dl_dst stored here on output. */
#define SIMON_REG_IDX_IP_PROTO  (11)
#define SIMON_REG_IDX_IP_SRC    (12)
#define SIMON_REG_IDX_IP_DST    (13)
#define SIMON_REG_IDX_TP_SRC    (14)
#define SIMON_REG_IDX_TP_DST    (15)

#define SIMON_REG(REGS, INDEX, MASK, SHIFT)	\
    ((REGS[INDEX] & MASK) >> SHIFT)

#define SIMON_REG32(regs, idx)     SIMON_REG(regs, idx, 0xffffffff, 0)
#define SIMON_REG16_HI(regs, idx)  SIMON_REG(regs, idx, 0xffff0000, 8)
#define SIMON_REG16_LO(regs, idx)  SIMON_REG(regs, idx, 0x0000ffff, 0)
#define SIMON_REG8_LO(regs, idx)   SIMON_REG(regs, idx, 0x000000ff, 0)

#define SIMON_REG_DL_TYPE(regs)   SIMON_REG16_LO(regs, SIMON_REG_IDX_DL_TYPE)

#define SIMON_REG_DL_SRC_LO(regs) SIMON_REG32(regs,    SIMON_REG_IDX_DL_SRC)
#define SIMON_REG_DL_SRC_HI(regs) SIMON_REG16_HI(regs, SIMON_REG_IDX_DL_SRC_HI)
#define SIMON_REG_DL_DST_LO(regs) SIMON_REG32(regs,    SIMON_REG_IDX_DL_DST)
#define SIMON_REG_DL_DST_HI(regs) SIMON_REG16_LO(regs, SIMON_REG_IDX_DL_DST_HI)


#define SIMON_REG_IP_PROTO(regs)  SIMON_REG8_LO(regs,  SIMON_REG_IDX_IP_PROTO)
#define SIMON_REG_IP_SRC(regs)    SIMON_REG32(regs,    SIMON_REG_IDX_IP_SRC)
#define SIMON_REG_IP_DST(regs)    SIMON_REG32(regs,    SIMON_REG_IDX_IP_DST)

#define SIMON_REG_TP_SRC(regs)    SIMON_REG16_LO(regs, SIMON_REG_IDX_TP_SRC)
#define SIMON_REG_TP_DST(regs)    SIMON_REG16_LO(regs, SIMON_REG_IDX_TP_DST)

#define SIMON_REG_OUT_DL_TYPE     (2)
#define SIMON_REG_OUT_DL_SRC_SRC  (3)
#define SIMON_REG_OUT_DL_SRC_DST  (4)
#define SIMON_REG_OUT_DL_DST_SRC  (5)
#define SIMON_REG_OUT_DL_DST_DST  (6)
#define SIMON_REG_OUT_IP_PROTO    (7)
#define SIMON_REG_OUT_IP_SRC_SRC  (8)
#define SIMON_REG_OUT_IP_SRC_DST  (9)
#define SIMON_REG_OUT_IP_DST_SRC (10)
#define SIMON_REG_OUT_IP_DST_DST (11)
#define SIMON_REG_OUT_TP_SRC_SRC (12)
#define SIMON_REG_OUT_TP_SRC_DST (13)
#define SIMON_REG_OUT_TP_DST_SRC (14)
#define SIMON_REG_OUT_TP_DST_DST (15)

#define SIMON_REG_COMPARE(REGS, IDX, PRED)  do {	 \
	regs[SIMON_REG_OUT_##IDX] = (PRED) ? 1 : 0;      \
    } while(0)

#define SIMON_REG_EQ(REGS, IDX, A, B) SIMON_REG_COMPARE(REGS, IDX, (A == B))

#endif
