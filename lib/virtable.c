
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
#include "util.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

#include "virtable.h"


VLOG_DEFINE_THIS_MODULE(virtable);

uint64_t virtable_update(struct virtable_map *vtm,
			 uint64_t virtable_id, uint64_t count, bool subtract);


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

    hmap_init(&vtm->hmap);

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
}


void virtable_map_destroy(struct virtable_map *vtm)
{
    int i;

    hmap_destroy(&vtm->hmap);

    /* Free all of the table blocks except the stub at index 0. */
    for(i = 1; i < VIRTABLE_MAX_BLOCKS; i++)
    {
	virtable_block_destroy(&vtm->blocks[i]);
    }
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
    struct virtable_block *blk = vtm->tail;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

    /* If our current block is out of space, allocate a new one. */
    if(blk->n >= blk->capacity) {

	VLOG_WARN_RL(&rl, "Allocating new virtable_block, table_id:  %"PRIu64 ", capacity:  %"PRIuSIZE,
		     table_id, 2 * blk->capacity);

	blk = virtable_alloc_new_block(vtm, 2 * blk->capacity);
    }

    /* By now we should have a table with some free space. */
    ovs_assert(blk->n < blk->capacity);

    /* Finally, get a new table from the current block. */
    vt = &blk->tables[blk->n++];
    virtable_table_init(vt, table_id, 0);

    hmap_insert_at(&vtm->hmap, &vt->hmap_node, table_id,
		   OVS_SOURCE_LOCATOR);
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
    return virtable_update(vtm, virtable_id, count, true);
}

bool virtable_exists(struct virtable_map *vtm, uint64_t virtable_id)
{
    struct virtable *vt = NULL;

    vt = CONTAINER_OF(hmap_first_with_hash(&vtm->hmap, virtable_id),
		      struct virtable, hmap_node);

    return (vt != NULL);
}


uint64_t
virtable_update(struct virtable_map *vtm,
		uint64_t table_id, uint64_t count, bool subtract)
{
    struct virtable *vt = NULL;
    uint64_t orig = 0;

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);

    vt = CONTAINER_OF(hmap_first_with_hash(&vtm->hmap, table_id),
		      struct virtable, hmap_node);

    /* If we don't have a virtable structure for this ID yet, create
     * one now.  This should only happen when adding new flows to
     * virtables manually (ie, at startup), not during normal packet
     * processing. */
    if(vt == NULL) {
	VLOG_WARN_RL(&rl, "Allocating new virtable on-the-fly for virtable_id %"PRIu64, table_id);

	virtable_alloc(vtm, table_id);

	vt = CONTAINER_OF(hmap_first_with_hash(&vtm->hmap, table_id),
			  struct virtable, hmap_node);
    }

    /* By now, we must have found a virtable for this ID */
    ovs_assert(vt != NULL);

    if(!subtract) {
	atomic_add(&vt->rule_count, count, &orig);
    } else {
	atomic_sub(&vt->rule_count, count, &orig);
    }


    return orig;
}
