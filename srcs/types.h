/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        types.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Type definitions
 */
#ifndef __WAE_TYPES_H
#define __WAE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

typedef struct _raw_buffer_s {
	unsigned char *buf;
	size_t size;
} raw_buffer_s;

typedef struct _crypto_element_s {
	raw_buffer_s *dek;
	raw_buffer_s *iv;
	bool is_migrated_app;
} crypto_element_s;

typedef struct _crypto_element_map_s crypto_element_map_s;

raw_buffer_s *buffer_create(size_t size);
raw_buffer_s *buffer_create_managed(unsigned char *buf, size_t size);
void buffer_destroy(raw_buffer_s *);
bool is_buffer_valid(const raw_buffer_s *);

crypto_element_s *crypto_element_create(raw_buffer_s *dek, raw_buffer_s *iv);
void crypto_element_destroy(crypto_element_s *c);
bool is_crypto_element_valid(const crypto_element_s *);

extern const size_t MAX_MAP_ELEMENT_SIZE;

void crypto_element_map_destroy(crypto_element_map_s *);
int crypto_element_map_add(crypto_element_map_s **map, const char *key, crypto_element_s *value);
void crypto_element_map_remove(crypto_element_map_s **map, const char *key);
crypto_element_s *crypto_element_map_get(crypto_element_map_s *map, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_TYPES_H */
