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
 * @file        key-handler.h
 * @author      Dongsun Lee (ds73.lee@samsung.com) 
 * @version     1.0
 * @brief       a header for key manupulatation.
 */



#ifndef __TIZEN_CORE_WAE_KEY_HANDLER_H
#define __TIZEN_CORE_WAE_KEY_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#define APP_DEK_ALIAS_PFX "APP_DEK_"

#define DEK_LEN 32
#define MAX_ALIAS_LEN 256
#define MAX_PKGID_LEN 256
#define MAX_PATH_LEN  512


#define RANDOM_FILE                        "/dev/urandom"
#define KEY_MANAGER_INITIAL_VALUE_DIR      "/opt/data/ckm/initial_values"
#define KEY_MANAGER_INITIAL_VALUE_FILE_PFX "WAE_APP_DEK"


int get_app_dek(const char* pPkgId, unsigned char** ppDek, int *dekLen);
int create_app_dek(const char* pPkgId, unsigned char** ppDek, int *dekLen);
int get_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen);
int create_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, int *dekLen);
int load_preloaded_app_deks();
int remove_app_dek(const char* pPkgId);


int _get_random(int length, unsigned char* random);
void _get_alias(const char* pPkgId, char* alias);
void _get_system_alias(const char* pPkgId, char* alias);
int _add_dek_to_key_manager(const char* pPkgId, const unsigned char* pDek, const int len);
int _write_initial_value_file(const char* pPkgId, const unsigned char* dek);
int _read_initial_value_file(const char* path, char* pkgId, unsigned char* dek);
int _get_initial_value_file_path(const char* pPkgId, char *path);


#ifdef __cplusplus
}
#endif
#endif /* __TIZEN_CORE_WAE_KEY_HANDLER_H */

