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
 * @file        key_manager.h
 * @author      Kyungwook Tak
 * @version     1.0
 * @brief       Serialize/deserialize crypto element and save/get to key-manager
 */
#ifndef __WAE_KEY_MANAGER_H
#define __WAE_KEY_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "web_app_enc.h"
#include "types.h"

int save_to_key_manager(const char *pkg_id, wae_app_type_e type, const crypto_element_s *ce);
int get_from_key_manager(const char *pkg_id, wae_app_type_e type, crypto_element_s **pce);
int remove_from_key_manager(const char *pkg_id, wae_app_type_e type);

bool is_app_deks_loaded_in_key_manager();
int set_app_deks_loaded_to_key_manager();
int clear_app_deks_loaded_from_key_manager();

#ifdef __cplusplus
}
#endif

#endif /* __WAE_KEY_MANAGER_H */
