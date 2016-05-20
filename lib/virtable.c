
/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2015 Nicira, Inc.
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
#include <limits.h>
#include "util.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

#include "virtable.h"

#include "increment_table_id.h"

#define VIRTABLE_RECLAIM_IDS 1

VLOG_DEFINE_THIS_MODULE(virtable);

uint64_t virtable_update(struct virtable_map *vtm,
			 uint64_t virtable_id, uint64_t count, bool subtract);

void virtable_swap_cmap(struct cmap *from, struct cmap *to,
			struct virtable *vt);


struct virtable_block *
virtable_alloc_new_block(struct virtable_map *vtm, size_t capacity);


static struct virtable virtable_stub[VIRTABLE_STUB_SIZE];



static inline void virtable_block_init(struct virtable_block *blk,
				       size_t capacity, struct virtable *vt)
{
    blk->n = 0;
    blk->capacity = capacity;
    blk->tables = vt;
}

static inline void virtable_block_destroy(struct virtable_block *blk)
{
    blk->n = 0;
    blk->capacity = 0;
    free(blk->tables);
}

static inline void virtable_table_init(struct virtable * vt,
				       uint64_t table_id, uint64_t count)

{
    vt->table_id = table_id;
    atomic_init(&vt->rule_count, count);
}


void virtable_map_init(struct virtable_map *vtm)
{
    int i;

    ovs_mutex_init(&vtm->mutex);
    cmap_init(&vtm->cmap);
    cmap_init(&vtm->cmap_unallocated);

    /* Initialize all blocks. */
    for(i = 0; i < VIRTABLE_MAX_BLOCKS; i++)
    {
	virtable_block_init(&vtm->blocks[i], 0, NULL);
    }

    /* Add the stub block to avoid malloc() for initial set of virtables. */
    vtm->blocks[0].tables = &virtable_stub[0];
    vtm->blocks[0].capacity = ARRAY_SIZE(virtable_stub);

    vtm->n = 1;
    vtm->tail = &vtm->blocks[0];

    /* We must have a table 0, so allocate it now. */
    virtable_alloc(vtm, 0);
}


void virtable_map_destroy(struct virtable_map *vtm)
{
    int i;

    cmap_destroy(&vtm->cmap);
    cmap_destroy(&vtm->cmap_unallocated);

    /* Free all of the table blocks except the stub at index 0. */
    for(i = 1; i < VIRTABLE_MAX_BLOCKS; i++)
    {
	virtable_block_destroy(&vtm->blocks[i]);
    }

    ovs_mutex_destroy(&vtm->mutex);
}

struct virtable_block *
virtable_alloc_new_block(struct virtable_map *vtm, size_t capacity)
{
    struct virtable *vt = xmalloc(capacity * sizeof(struct virtable));
    struct virtable_block *blk = &vtm->blocks[vtm->n++];

    ovs_assert(vtm->n < VIRTABLE_MAX_BLOCKS);

    virtable_block_init(blk, capacity, vt);
    vtm->tail = blk;

    return blk;
}

/* Get a new table entry */
void
virtable_alloc(struct virtable_map *vtm, uint64_t table_id)
{
    struct virtable *vt;
    struct virtable_block *blk;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

    ovs_mutex_lock(&vtm->mutex);

    blk= vtm->tail;

    /* If our current block is out of space, allocate a new one. */
    if(blk->n >= blk->capacity) {
	VLOG_WARN_RL(&rl, "Allocating new virtable_block, table_id:  %"PRIu64 ", capacity:  %"PRIuSIZE,
		     table_id, 2 * blk->capacity);

	blk = virtable_alloc_new_block(vtm, 2 * blk->capacity);
    }

    /* By now we should have a table with some free space. */
    ovs_assert(blk->n < blk->capacity);

    /* Check to make sure this virtable hasn't already been allocated.
     * This can happen if the flow_mod gets evaluated before this
     * action, which apparently does happen. */
    if(cmap_find(&vtm->cmap, table_id) == NULL) {

	/* Finally, get a new table from the current block. */
	vt = &blk->tables[blk->n++];
	virtable_table_init(vt, table_id, 0);

	/* Hash field is only of type uint32_t, so we can only support
	 * hash values up to that size */
	ovs_assert(table_id < UINT32_MAX);

	cmap_insert(&vtm->cmap, &vt->cmap_node, table_id);
    } else {
	VLOG_WARN_RL(&rl, "Entry for virtable %"PRIu64 "already exists, not adding new virtable.",
		     table_id);
    }

    ovs_mutex_unlock(&vtm->mutex);
}

/* Swap a virtable entry between two cmaps.
 * NOTE:  Caller must already hold the mutex associated with both
 * cmaps before invoking this function.
 */
void virtable_swap_cmap(struct cmap *from, struct cmap *to,
			struct virtable *vt)
{
    ovs_assert(cmap_find(from, vt->table_id) != NULL);
    ovs_assert(cmap_find(to,   vt->table_id) == NULL);

    cmap_remove(from, &vt->cmap_node, vt->table_id);
    cmap_insert(to,   &vt->cmap_node, vt->table_id);
}


bool virtable_next_id(struct virtable_map *vtm, uint64_t *val)
{
    bool found = false;

    if(cmap_count(&vtm->cmap_unallocated) != 0) {
	struct cmap_node *node;
	struct virtable *vt;

	ovs_mutex_lock(&vtm->mutex);
	node = cmap_first(&vtm->cmap_unallocated);

	if(node != NULL) {
	    uint64_t count;
	    vt = CONTAINER_OF(node, struct virtable, cmap_node);

	    ovs_assert(vt != NULL);

	    atomic_read(&vt->rule_count, &count);
	    ovs_assert(count == 0);

	    *val = vt->table_id;
	    found = true;

	    /* Move the entry into the allocated hash table. */
	    virtable_swap_cmap(&vtm->cmap_unallocated, &vtm->cmap, vt);
	}
	ovs_mutex_unlock(&vtm->mutex);
    }

    return found;
}

uint64_t
virtable_get(struct virtable_map *vtm,
	     uint64_t virtable_id)
{
    return virtable_update(vtm, virtable_id, 0, false);
}


uint64_t
virtable_increment(struct virtable_map *vtm,
	     uint64_t virtable_id, uint64_t count)
{
    return virtable_update(vtm, virtable_id, count, false);
}

uint64_t
virtable_decrement(struct virtable_map *vtm,
		   uint64_t virtable_id, uint64_t count)
{
    uint64_t orig = virtable_update(vtm, virtable_id, count, true);

    return orig;
}

bool virtable_exists(struct virtable_map *vtm, uint64_t virtable_id)
{
    struct virtable *vt = NULL;

    vt = CONTAINER_OF(cmap_find(&vtm->cmap, virtable_id),
		      struct virtable, cmap_node);

    return (vt != NULL);
}

static inline struct virtable *virtable_find_cmap(struct cmap *cmap, uint64_t table_id)
{
    return CONTAINER_OF(cmap_find(cmap, table_id), struct virtable, cmap_node);
}

uint64_t
virtable_update(struct virtable_map *vtm,
		uint64_t table_id, uint64_t count, bool subtract)
{
    struct virtable *vt = NULL;
    uint64_t orig = 0;

    static struct vlog_rate_limit rl OVS_UNUSED = VLOG_RATE_LIMIT_INIT(10, 10);

    vt = CONTAINER_OF(cmap_find(&vtm->cmap, table_id),
		      struct virtable, cmap_node);

    /* If we don't have a virtable structure for this ID yet, create
     * one now.  This should only happen when adding new flows to
     * virtables manually (ie, at startup), not during normal packet
     * processing. */
    if ((count != 0) && (vt == NULL)) {
	/* If we haven't found a virtable yet, check for it first in the unallocated pool. */
	struct virtable *vt_unalloc = virtable_find_cmap(&vtm->cmap_unallocated, table_id);

	if (vt_unalloc != NULL) {
	    ovs_mutex_lock(&vtm->mutex);
	    virtable_swap_cmap(&vtm->cmap_unallocated, &vtm->cmap, vt_unalloc);
	    ovs_mutex_unlock(&vtm->mutex);

	    VLOG_WARN_RL(&rl, "Reclaiming new virtable on-the-fly for virtable_id %"PRIu64, table_id);
	    vt = vt_unalloc;
	} else {
	    VLOG_WARN_RL(&rl, "Allocating new virtable on-the-fly for virtable_id %"PRIu64, table_id);
	    virtable_alloc(vtm, table_id);

	    vt = CONTAINER_OF(cmap_find(&vtm->cmap, table_id),
			      struct virtable, cmap_node);
	}
    }

    if (count != 0) {
	/* By now, we must have found a virtable for this ID */
	ovs_assert(vt != NULL);

	if(!subtract) {
	    atomic_add(&vt->rule_count, count, &orig);
	} else {
	    atomic_sub(&vt->rule_count, count, &orig);

#ifdef VIRTABLE_RECLAIM_IDS
	    /* Make sure our counter didn't wrap, which would inciate
	     * something very bad happened.  */
	    ovs_assert(orig - count < orig);

	    /* If the count for this rule reached zero, move this
	     * entry to the unallocated pool. */
	    if(orig - count == 0) {
		ovs_mutex_lock(&vtm->mutex);
		virtable_swap_cmap(&vtm->cmap, &vtm->cmap_unallocated, vt);
		ovs_mutex_unlock(&vtm->mutex);
	    }
#endif

	}
    } else {
	if (vt != NULL) {
	    atomic_read(&vt->rule_count, &orig);
	} else {
#if 0
	    VLOG_WARN_RL(&rl, "No cmap entry found for virtable_id %"PRIu64", returning zero count",
			 table_id);
#endif
	    orig = 0;
	}
    }


    return orig;
}
