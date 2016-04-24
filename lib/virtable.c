
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

#include "util.h"

#include "virtable.h"

void virtable_map_init(struct virtable_map *vtm)
{
    hmap_init(&vtm->hmap);

    vtm->tables = vtm->stub;
    vtm->n = 0;
}


void virtable_map_destroy(struct virtable_map *vtm)
{
    hmap_destroy(&vtm->hmap);
}

void virtable_alloc(struct virtable_map *vtm, uint64_t table_id)
{
    struct virtable *vt = &vtm->tables[vtm->n++];

    ovs_assert(vtm->n < VIRTABLE_STUB_SIZE);

    vt->table_id = table_id;
    atomic_init(&vt->rule_count, 0);

    hmap_insert_fast(&vtm->hmap, &vt->hmap_node, table_id);
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

    atomic_add(&vt->rule_count, delta, &orig);

    return orig;
}
