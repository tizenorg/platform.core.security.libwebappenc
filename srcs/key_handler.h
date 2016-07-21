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
 * @file        key_handler.h
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       Key manupulatation.
 */
#ifndef __WAE_KEY_HANDLER_H
#define __WAE_KEY_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>

#include "web_app_enc.h"
#include "types.h"

#define MAX_PATH_LEN  512

/* functions with "_" prefix are internal static functions but declared here for testing */
void _remove_app_ce_from_cache(const char *pkg_id);
int _get_random(raw_buffer_s *rb);
int _get_preloaded_app_dek_file_path(const char *pkg_id, size_t size, char *path);
int _read_encrypted_app_dek_from_file(const char *pkg_id, raw_buffer_s **pencrypted);
int _write_encrypted_app_dek_to_file(const char *pkg_id, const raw_buffer_s *encrypted);

/* functions for interface */
int get_app_ce(const char *pkg_id, wae_app_type_e app_type, bool create_for_migrated_app,
			   const crypto_element_s **pce);
int create_app_ce(const char *pkg_id, wae_app_type_e app_type,
				  const crypto_element_s **pce);
int get_preloaded_app_ce(const char *pkg_id, const crypto_element_s **pce);
int create_preloaded_app_ce(const char *pkg_id, const crypto_element_s **pce);
int load_preloaded_app_deks(bool reload);
int remove_app_ce(const char *pkg_id, wae_app_type_e app_type);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_KEY_HANDLER_H */
