
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

#include "virtable.h"

void virtable_map_init(struct virtable_map *vtm)
{
    ovs_mutex_init(&vtm->mutex);

    hmap_init(&vtm->hmap);

    vtm->n = 0;
    vtm->tables = vtm->stub;
    vtm->capacity = VIRTABLE_STUB_SIZE;
}


void virtable_map_destroy(struct virtable_map *vtm)
{
    hmap_destroy(&vtm->hmap);
}

void virtable_alloc(struct virtable_map *vtm, uint64_t table_id)
{
    struct virtable *vt;

    //ovs_assert(vtm->n < VIRTABLE_STUB_SIZE);

    if(vtm->n >= vtm->capacity) {
	size_t i;
	size_t old_size, new_size;
	struct virtable *new_virtables, *old_virtables;

	old_virtables = vtm->tables;

	ovs_mutex_lock(&vtm->mutex);

	old_size = vtm->capacity * sizeof(struct virtable);
	new_size = (2 * vtm->capacity) * sizeof(struct virtable);

	if(vtm->capacity == VIRTABLE_STUB_SIZE) {
	    new_virtables = xmalloc(new_size);

	    memcpy(new_virtables, vtm->stub, old_size);
	} else {
	    new_virtables = xrealloc(vtm->tables, new_size);
	}

	/* Update all of the hmap entries to point to our new memory. */
	for(i = 0; i < vtm->n; i++)
	{
	    hmap_node_moved(&vtm->hmap,
			    &old_virtables[i].hmap_node,
			    &new_virtables[i].hmap_node);
	}

	vtm->tables = new_virtables;
	vtm->capacity = 2 * vtm->capacity;

	ovs_mutex_unlock(&vtm->mutex);
    }

    vt = &vtm->tables[vtm->n++];

    vt->table_id = table_id;
    atomic_init(&vt->rule_count, 0);

    hmap_insert_at(&vtm->hmap, &vt->hmap_node, table_id,
		   OVS_SOURCE_LOCATOR);
}

uint64_t
virtable_update(struct virtable_map *vtm,
		uint64_t table_id, uint64_t delta)
{
    struct virtable *vt = NULL;
    uint64_t orig = 0;

    vt = CONTAINER_OF(hmap_first_with_hash(&vtm->hmap, table_id),
		      struct virtable, hmap_node);

    ovs_assert(vt != NULL);

    /* If we are updating the virtable counter, we need to lock
     * the data structure first in case it's being reallocated.
     * If reallocation is happening while we're just reading, we
     * should be safe, since we'll just be reading the old value. */
    if(delta != 0) {
	ovs_mutex_lock(&vtm->mutex);
    }

    atomic_add(&vt->rule_count, delta, &orig);

    if(delta != 0) {
	ovs_mutex_unlock(&vtm->mutex);
    }


    return orig;
}
