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
 * @file        web_app_enc.c
 * @author      Dongsun Lee (ds73.lee@samsung.com) 
 * @version     1.0
 * @brief       provides fucntions for encryption and decryption of web application.
 */

#include <stdlib.h>
#include <stdio.h>

#include "web_app_enc.h"
#include "key_handler.h"
#include "crypto_service.h"
#include "wae_log.h"


int _wae_encrypt_downloaded_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen,
                                unsigned char** ppEncryptedData, int* pEncDataLen)
{
    int ret = WAE_ERROR_NONE;
    unsigned char *pDek = NULL;
    int dekLen = -1;    

    if(pPkgId == NULL) {
        WAE_SLOGE("Invalid Parameter. pPkgId is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(pData == NULL || dataLen <= 0) {
        WAE_SLOGE("Invalid Parameter. pData is NULL or invalid dataLen(%d)", dataLen);
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(ppEncryptedData == NULL || pEncDataLen == NULL) {
        WAE_SLOGE("Invalid Parameter. ppEncryptedData or pEncDataLen is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }

    // get APP_DEK.
    //   if not exists, create APP_DEK
    ret = get_app_dek(pPkgId, &pDek, &dekLen);
    if(ret == WAE_ERROR_NO_KEY) {
        ret = create_app_dek(pPkgId, &pDek, &dekLen);
    }
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

    // encrypt 
    ret = encrypt_aes_cbc(pDek, dekLen, pData, dataLen, ppEncryptedData, pEncDataLen);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

error:
    if(pDek != NULL)
        free(pDek);

    return ret;
}

int _wae_decrypt_downloaded_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen,
                                unsigned char** ppDecryptedData, int* pDecDataLen)
{
    int ret = WAE_ERROR_NONE;
    unsigned char *pDek = NULL;
    int dekLen = -1;    

    if(pPkgId == NULL) {
        WAE_SLOGE("Invalid Parameter. pPkgId is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(pData == NULL || dataLen <= 0) {
        WAE_SLOGE("Invalid Parameter. pData is NULL or invalid dataLen(%d)", dataLen);
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(ppDecryptedData == NULL || pDecDataLen == NULL) {
        WAE_SLOGE("Invalid Parameter. ppDecryptedData or pDecDataLen is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }

    ret = get_app_dek(pPkgId, &pDek, &dekLen);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

    // decrypt 
    ret = decrypt_aes_cbc(pDek, dekLen, pData, dataLen, ppDecryptedData, pDecDataLen);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }
    
error:
    if(pDek != NULL)
        free(pDek);

    return ret;
}

int _wae_encrypt_preloaded_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen,
                                unsigned char** ppEncryptedData, int* pEncDataLen)
{

    int ret = WAE_ERROR_NONE;
    unsigned char *pDek = NULL;
    int dekLen = -1;

    if(pPkgId == NULL) {
        WAE_SLOGE("Invalid Parameter. pPkgId is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(pData == NULL || dataLen <= 0) {
        WAE_SLOGE("Invalid Parameter. pData is NULL or invalid dataLen(%d)", dataLen);
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }
    if(ppEncryptedData == NULL || pEncDataLen == NULL) {
        WAE_SLOGE("Invalid Parameter. ppEncryptedData or pEncDataLen is NULL");
        ret = WAE_ERROR_INVALID_PARAMETER;
        goto error;
    }

    ret = get_preloaded_app_dek(pPkgId, &pDek, &dekLen);
    if(ret == WAE_ERROR_NO_KEY) {
        ret = create_preloaded_app_dek(pPkgId, &pDek, &dekLen);
    }
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

    // encrypt
    ret = encrypt_aes_cbc(pDek, dekLen, pData, dataLen, ppEncryptedData, pEncDataLen);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }
error:
    if(pDek != NULL)
        free(pDek);

    return ret;
}

int _wae_decrypt_preloaded_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen,
                                unsigned char** ppDecryptedData, int* pDecDataLen)
{
    // same with the decryption of downloaded web application
    return _wae_decrypt_downloaded_web_application(pPkgId, pData, dataLen, ppDecryptedData, pDecDataLen);
}

int wae_encrypt_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen,
                                unsigned char** ppEncryptedData, int* pEncDataLen,
                                const int isPreloaded)
{
    int ret = WAE_ERROR_NONE;
    if(isPreloaded)
        ret = _wae_encrypt_preloaded_web_application(pPkgId, pData, dataLen, ppEncryptedData, pEncDataLen);
    else
        ret = _wae_encrypt_downloaded_web_application(pPkgId, pData, dataLen, ppEncryptedData, pEncDataLen);
    return ret;
}

int wae_decrypt_web_application(const char* pPkgId,
                                const unsigned char* pData, const int dataLen, 
                                unsigned char** ppDecryptedData, int* pDecDataLen, 
                                const int isPreloaded)
{
    int ret = WAE_ERROR_NONE;
    if(isPreloaded)
        ret = _wae_decrypt_preloaded_web_application(pPkgId, pData, dataLen, ppDecryptedData, pDecDataLen);
    else
        ret =_wae_decrypt_downloaded_web_application(pPkgId, pData, dataLen, ppDecryptedData, pDecDataLen);
    WAE_SLOGI("");
    return ret;
}


int wae_remove_app_dek(const char* pPkgId)
{
    int ret = WAE_ERROR_NONE;
    ret = remove_app_dek(pPkgId);
    return ret;
}
