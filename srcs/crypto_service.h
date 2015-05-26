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
 * @file        crypto-service.h
 * @author      Dongsun Lee (ds73.lee@samsung.com) 
 * @version     1.0
 * @brief       a header for key manupulatation.
 */



#ifndef __TIZEN_CORE_WAE_CRYPTO_SERVICE_H
#define __TIZEN_CORE_WAE_CRYPTO_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif


int encrypt_aes_cbc(const unsigned char* pKey, const int keyLen, const unsigned char* pData, const int dataLen, unsigned char** ppEncryptedData, int* pEncDataLen);

int decrypt_aes_cbc(const unsigned char* pKey, const int keyLen, const unsigned char* pData, const int dataLen, unsigned char** ppDecryptedData, int* pDecDataLen);

#ifdef __cplusplus
}
#endif
#endif /* __TIZEN_CORE_WAE_CRYPTO_SERVICE_H */

