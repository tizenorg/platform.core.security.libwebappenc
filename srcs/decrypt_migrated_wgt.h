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
 * @file        decrypt_migrated_wgt.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Restore old encryption key for removed secure-storage
 */
#ifndef __WAE_SS_KEY_GENERATOR_H
#define __WAE_SS_KEY_GENERATOR_H

#include <stddef.h>

int decrypt_by_old_ss_algo(const char *pkg_id,
						   const unsigned char *encrypted, size_t encrypted_len,
						   unsigned char **pdecrypted, size_t *pdecrypted_len);

#endif /* __WAE_SS_KEY_GENERATOR_H */
