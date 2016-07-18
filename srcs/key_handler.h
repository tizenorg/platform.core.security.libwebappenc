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

#define MAX_PATH_LEN  512

/* functions with "_" prefix are internal static functions but declared here for testing */
void _initialize_cache();
const unsigned char *_get_app_dek_from_cache(const char *pkg_id);
void _add_app_dek_to_cache(const char *pkg_id, const unsigned char *dek);
void _remove_app_dek_from_cache(const char *pkg_id);
int _get_random(size_t length, unsigned char *random);
void _get_alias(const char *pkg_id, wae_app_type_e app_type, bool forSave, char *alias, size_t buff_len);
void _get_dek_kek_alias(char *alias, size_t buff_len);
void _get_dek_loading_done_alias(char *alias, size_t buff_len);
const char *_get_dek_kek_pub_key_path();
const char *_get_dek_kek_pri_key_path();
const char *_get_dek_store_path();
int _add_dek_to_key_manager(const char *pkg_id, wae_app_type_e app_type, const unsigned char *dek, size_t dek_len);
int _get_preloaded_app_dek_file_path(const char *pkg_id, size_t size, char *path);
int _extract_pkg_id_from_file_name(const char *file_name, char *pkg_id);
int _read_encrypted_app_dek_from_file(const char *pkg_id, unsigned char **pencrypted_app_dek, size_t *pencrypted_app_dek_len);
int _write_encrypted_app_dek_to_file(const char *pkg_id, const unsigned char *encrypted_app_dek, size_t encrypted_app_dek_len);
int _read_from_file(const char *path, unsigned char **pdata, size_t *pdata_len);
int _write_to_file(const char *path, const unsigned char *data, size_t data_len);
int _get_app_deks_loaded();
int _set_app_deks_loaded();
int _clear_app_deks_loaded();

/* functions for interface */
int get_app_dek(const char *pkg_id, wae_app_type_e app_type, unsigned char **pdek, size_t *pdek_len);
int create_app_dek(const char *pkg_id, wae_app_type_e app_type, unsigned char **pdek, size_t *pdek_len);
int get_preloaded_app_dek(const char *pkg_id, unsigned char **pdek, size_t *pdek_len);
int create_preloaded_app_dek(const char *pkg_id, unsigned char **pdek, size_t *pdek_len);
int load_preloaded_app_deks(bool reload);
int remove_app_dek(const char *pkg_id, wae_app_type_e app_type);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_KEY_HANDLER_H */
