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
 * @file        crypto_service.h
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       provides encryption and decription operations.
 */
#ifndef __WAE_CRYPTO_SERVICE_H
#define __WAE_CRYPTO_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

int encrypt_app_dek(const unsigned char *pubkey, size_t pubkey_len,
					const unsigned char *dek, size_t dek_len,
					unsigned char **encryptedDek, size_t *encryptedDekLen);

int decrypt_app_dek(const unsigned char *prikey, size_t prikey_len,
					const char *prikey_pass,
					const unsigned char *encrypted_dek, size_t encrypted_dek_len,
					unsigned char **pdecrypted_dek, size_t *pdecrypted_dek_len);


int encrypt_aes_cbc(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char **pencrypted_data, size_t *pencrypted_data_len);

int decrypt_aes_cbc(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char **pdecrypted_data, size_t *pdecrypted_data_len);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_CRYPTO_SERVICE_H */
