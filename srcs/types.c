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
 * @file        types.c
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Type definitions
 */
#include "types.h"

#include <stdlib.h>
#include <string.h>

#include "wae_log.h"
#include "web_app_enc.h"

const size_t MAX_MAP_ELEMENT_SIZE = 20;

raw_buffer_s *buffer_create(size_t size)
{
	raw_buffer_s *rb = (raw_buffer_s *)malloc(sizeof(raw_buffer_s));
	if (rb == NULL)
		return NULL;

	rb->buf = (unsigned char *)malloc(sizeof(unsigned char) * size);
	if (rb->buf == NULL) {
		free(rb);
		return NULL;
	}

	memset(rb->buf, 0x00, size);

	rb->size = size;

	return rb;
}

raw_buffer_s *buffer_create_managed(unsigned char *buf, size_t size)
{
	if (buf == NULL || size == 0)
		return NULL;

	raw_buffer_s *rb = (raw_buffer_s *)malloc(sizeof(raw_buffer_s));
	if (rb == NULL)
		return NULL;

	rb->buf = buf;
	rb->size = size;

	return rb;
}

void buffer_destroy(raw_buffer_s *rb)
{
	if (rb == NULL)
		return;

	free(rb->buf);
	free(rb);
}

bool is_buffer_valid(const raw_buffer_s *rb)
{
	return rb != NULL && rb->buf != NULL && rb->size != 0;
}

crypto_element_s *crypto_element_create(raw_buffer_s *dek, raw_buffer_s *iv)
{
	if (dek == NULL || iv == NULL)
		return NULL;

	crypto_element_s *ce = (crypto_element_s *)malloc(sizeof(crypto_element_s));
	if (ce == NULL)
		return NULL;

	ce->dek = dek;
	ce->iv = iv;
	ce->is_migrated_app = false;

	return ce;
}

void crypto_element_destroy(crypto_element_s *ce)
{
	if (ce == NULL)
		return;

	buffer_destroy(ce->dek);
	buffer_destroy(ce->iv);
	free(ce);
}

bool is_crypto_element_valid(const crypto_element_s *ce)
{
	return ce != NULL && is_buffer_valid(ce->dek) && is_buffer_valid(ce->iv);
}

struct _crypto_element_map_s {
	char *key;
	crypto_element_s *value;
	crypto_element_map_s *next;
};

static crypto_element_map_s *crypto_element_map_create()
{
	crypto_element_map_s *cem = (crypto_element_map_s *)malloc(sizeof(crypto_element_map_s));
	if (cem == NULL)
		return NULL;

	cem->key = NULL;
	cem->value = NULL;
	cem->next = NULL;

	return cem;
}

void crypto_element_map_destroy(crypto_element_map_s *cem)
{
	if (cem == NULL)
		return;

	crypto_element_map_s *current = cem;
	while (current) {
		WAE_SLOGD("Destroy crypto element of key(%s)", current->key);
		crypto_element_map_s *tmp = current->next;

		free(current->key);
		crypto_element_destroy(current->value);
		free(current);

		current = tmp;
	}
}

int crypto_element_map_add(crypto_element_map_s **map,
							const char *key, crypto_element_s *value)
{
	if (map == NULL || key == NULL || !is_crypto_element_valid(value))
		return WAE_ERROR_INVALID_PARAMETER;

	crypto_element_map_s *last = *map;
	size_t count = 0;
	for (crypto_element_map_s *current = *map; current != NULL; current = current->next) {
		if (strcmp(current->key, key) == 0) {
			WAE_SLOGD("Update value to map on existing key(%s)", key);
			crypto_element_destroy(current->value);
			current->value = value;
			return WAE_ERROR_NONE;
		}

		++count;
		last = current;
	}

	WAE_SLOGD("Add value to map on new key(%s)", key);
	crypto_element_map_s *e = crypto_element_map_create();
	if (e == NULL)
		return WAE_ERROR_MEMORY;

	e->key = strdup(key);
	if (e->key == NULL) {
		free(e);
		return WAE_ERROR_MEMORY;
	}

	e->value = value;
	e->next = NULL;

	if (last == NULL)
		*map = e;
	else
		last->next = e;

	if (count == MAX_MAP_ELEMENT_SIZE) {
		WAE_SLOGD("Map size touched max! Remove one element from the front(%s)",
				  (*map)->key);

		crypto_element_map_s *next = (*map)->next;

		crypto_element_destroy((*map)->value);
		free((*map)->key);
		free(*map);

		*map = next;
	}

	return WAE_ERROR_NONE;
}

void crypto_element_map_remove(crypto_element_map_s **map, const char *key)
{
	if (map == NULL || key == NULL)
		return;

	if (*map == NULL) {
		WAE_SLOGD("Map is empty so remove operation ignored for key(%s)", key);
		return;
	}

	crypto_element_map_s *before = NULL;
	crypto_element_map_s *current = *map;
	while (current) {
		if (strcmp(key, current->key) != 0) {
			before = current;
			current = current->next;
			continue;
		}

		WAE_SLOGD("Removing value mapped by key(%s)", key);

		crypto_element_map_s *next = current->next;

		free(current->key);
		crypto_element_destroy(current->value);
		free(current);

		if (before == NULL)
			*map = next;
		else
			before->next = next;

		break;
	}
}

crypto_element_s *crypto_element_map_get(crypto_element_map_s *map, const char *key)
{
	if (map == NULL || key == NULL) {
		WAE_SLOGD("Map is empty so nothing to get.");
		return NULL;
	}

	for (crypto_element_map_s *current = map; current != NULL; current = current->next) {
		if (strcmp(key, current->key) == 0) {
			WAE_SLOGD("Getting value mapped by key(%s)", key);
			return current->value;
		}
	}

	WAE_SLOGD("Cannot get value mapped by key(%s). No mapped value!", key);
	return NULL;
}
