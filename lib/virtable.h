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

#ifndef VIRTABLE_H
#define VIRTABLE_H 1

#include <stdlib.h>

#include "cmap.h"
#include "ovs-atomic.h"
#include "openvswitch/thread.h"

//struct virtable_block;
//struct virtable_map;

#define VIRTABLE_STUB_SIZE (16)
#define VIRTABLE_MAX_BLOCKS (64)

struct virtable {
    struct cmap_node cmap_node;
    uint64_t table_id;
    atomic_ullong rule_count;
};

struct virtable_block {
    size_t n;
    size_t capacity;

    struct virtable *tables;
};

struct virtable_map {
    struct cmap cmap;             /* Hash map for all table etries. */

    size_t n;                     /* Count of currently allocated table blocks. */
    struct virtable_block *tail;  /* Current virtable block for new entries. */

    /* Pointers to all table blocks. */
    struct virtable_block blocks[VIRTABLE_MAX_BLOCKS];
};


void virtable_map_init(struct virtable_map *vtm);
void virtable_map_destroy(struct virtable_map *vtm);

void virtable_alloc(struct virtable_map *vtm, uint64_t table_id);

uint64_t virtable_increment(struct virtable_map *vtm,
			    uint64_t virtable_id, uint64_t count);

uint64_t virtable_decrement(struct virtable_map *vtm,
			    uint64_t virtable_id, uint64_t count);


uint64_t virtable_get(struct virtable_map *vtm,
		      uint64_t virtable_id);

bool virtable_exists(struct virtable_map *vtm, uint64_t virtable_id);

#endif
