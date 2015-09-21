/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @brief       a header for key manupulatation.
 */



#ifndef __TIZEN_CORE_WAE_KEY_HANDLER_H
#define __TIZEN_CORE_WAE_KEY_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "web_app_enc.h"

#define APP_DEK_ALIAS_PFX "APP_DEK_"
#define APP_DEK_LOADING_DONE_ALIAS "APP_DEKS_LOADING_FINISHED"

#define DEK_LEN 32
#define MAX_ALIAS_LEN 256
#define MAX_PKGID_LEN 256
#define MAX_PATH_LEN  512
#define MAX_CACHE_SIZE 100


#define RANDOM_FILE        "/dev/urandom"
#define APP_DEK_FILE_PFX   "WAE_APP_DEK"
#define APP_DEK_KEK_ALIAS  "WAE_APP_DEK_KEK"

#define WAE_TRUE  1
#define WAE_FALSE 0

void _initialize_cache();
unsigned char* _get_app_dek_from_cache(const char* pkgId);
void _add_app_dek_to_cache(const char* pkgId, unsigned char* dek);
void _remove_app_dek_from_cache(const char* pkgId);
int _get_random(size_t length, unsigned char* random);
void _get_alias(const char* pPkgId, wae_app_type_e appType, int forSave, char* alias, size_t buff_len);
void _get_dek_kek_alias(char* alias, size_t buff_len);
void _get_dek_loading_done_alias(char* alias, size_t buff_len);
const char* _get_dek_kek_pub_key_path();
const char* _get_dek_kek_pri_key_path();
const char* _get_dek_store_path();
int _add_dek_to_key_manager(const char* pPkgId, wae_app_type_e appType, const unsigned char* pDek, size_t len);
int _get_preloaded_app_dek_file_path(const char* pPkgId, char *path);
int _extract_pkg_id_from_file_name(const char* fileName, char* pkgId);
int _read_encrypted_app_dek_from_file(const char* pPkgId, unsigned char** encrypted_app_dek, size_t*len);
int _write_encrypted_app_dek_to_file(const char* pPkgId, const unsigned char* encrypted_app_dek, size_t len);
int _read_from_file(const char* path, unsigned char** data, size_t* len);
int _write_to_file(const char* path, const unsigned char* data, size_t len);
int _get_app_dek_kek_from_key_manager(unsigned char** ppDekKek, size_t* kekLen);
int _get_app_deks_loaded();
int _set_app_deks_loaded();
int _clear_app_deks_loaded();

int get_app_dek(const char* pPkgId, wae_app_type_e appType, unsigned char** ppDek, size_t *dekLen);
int create_app_dek(const char* pPkgId, wae_app_type_e appType, unsigned char** ppDek, size_t *dekLen);
int get_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, size_t* dekLen);
int create_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, size_t *dekLen);
int load_preloaded_app_deks(int reload);
int remove_app_dek(const char* pPkgId, wae_app_type_e appType);


#ifdef __cplusplus
}
#endif
#endif /* __TIZEN_CORE_WAE_KEY_HANDLER_H */

