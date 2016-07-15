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
unsigned char *_get_app_dek_from_cache(const char *pkgId);
void _add_app_dek_to_cache(const char *pkgId, unsigned char *dek);
void _remove_app_dek_from_cache(const char *pkgId);
int _get_random(size_t length, unsigned char *random);
void _get_alias(const char *pPkgId, wae_app_type_e appType, bool forSave, char *alias, size_t buff_len);
void _get_dek_kek_alias(char *alias, size_t buff_len);
void _get_dek_loading_done_alias(char *alias, size_t buff_len);
const char *_get_dek_kek_pub_key_path();
const char *_get_dek_kek_pri_key_path();
const char *_get_dek_store_path();
int _add_dek_to_key_manager(const char *pPkgId, wae_app_type_e appType, const unsigned char *pDek, size_t len);
int _get_preloaded_app_dek_file_path(const char *pPkgId, size_t size, char *path);
int _extract_pkg_id_from_file_name(const char *fileName, char *pkgId);
int _read_encrypted_app_dek_from_file(const char *pPkgId, unsigned char **encrypted_app_dek, size_t *len);
int _write_encrypted_app_dek_to_file(const char *pPkgId, const unsigned char *encrypted_app_dek, size_t len);
int _read_from_file(const char *path, unsigned char **data, size_t *len);
int _write_to_file(const char *path, const unsigned char *data, size_t len);
int _get_app_deks_loaded();
int _set_app_deks_loaded();
int _clear_app_deks_loaded();

/* functions for interface */
int get_app_dek(const char *pPkgId, wae_app_type_e appType, unsigned char **ppDek, size_t *dekLen);
int create_app_dek(const char *pPkgId, wae_app_type_e appType, unsigned char **ppDek, size_t *dekLen);
int get_preloaded_app_dek(const char *pPkgId, unsigned char **ppDek, size_t *dekLen);
int create_preloaded_app_dek(const char *pPkgId, unsigned char **ppDek, size_t *dekLen);
int load_preloaded_app_deks(bool reload);
int remove_app_dek(const char *pPkgId, wae_app_type_e appType);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_KEY_HANDLER_H */
