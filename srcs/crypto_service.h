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

int encrypt_app_dek(const unsigned char *rsaPublicKey, size_t pubKeyLen,
					const unsigned char *dek, size_t dekLen,
					unsigned char **encryptedDek, size_t *encryptedDekLen);

int decrypt_app_dek(const unsigned char *rsaPrivateKey, size_t priKeyLen,
					const char *priKeyPassword,
					const unsigned char *encryptedDek, size_t dencryptedDekLen,
					unsigned char **decryptedDek, size_t *decryptedDekLen);


int encrypt_aes_cbc(const unsigned char *pKey, size_t keyLen,
					const unsigned char *pData, size_t dataLen,
					unsigned char **ppEncryptedData, size_t *pEncDataLen);

int decrypt_aes_cbc(const unsigned char *pKey, size_t keyLen,
					const unsigned char *pData, size_t dataLen,
					unsigned char **ppDecryptedData, size_t *pDecDataLen);

#ifdef __cplusplus
}
#endif

#endif /* __WAE_CRYPTO_SERVICE_H */
