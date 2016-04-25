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

#include "hmap.h"
#include "ovs-atomic.h"
#include "openvswitch/thread.h"



struct virtable {
    struct hmap_node hmap_node;
    uint64_t table_id;
    atomic_ullong rule_count;
};

#define VIRTABLE_STUB_SIZE (16)

struct virtable_map {
    struct hmap hmap;
    struct virtable *tables;

    size_t n;
    size_t capacity;
    struct virtable stub[VIRTABLE_STUB_SIZE];

    struct ovs_mutex mutex;
};

void virtable_map_init(struct virtable_map *vtm);
void virtable_map_destroy(struct virtable_map *vtm);

void virtable_alloc(struct virtable_map *vtm, uint64_t table_id);

uint64_t virtable_update(struct virtable_map *vtm,
			 uint64_t table_id, uint64_t delta);

#endif
