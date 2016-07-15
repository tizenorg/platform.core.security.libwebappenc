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
 * @file    web_app_enc.h
 * @version 1.0
 * @brief   APIs of WEB_APP_ENC module.
*/
#ifndef __WEB_APP_ENC__
#define __WEB_APP_ENC__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * @addtogroup CAPI_WEB_APP_ENC_MODULE
 * @{
 */

/**
 * @brief WAE Errors.
 * @since_tizen 3.0
 */
typedef enum {
	WAE_ERROR_NONE                     = 0x00,  /**< Successful */
	WAE_ERROR_INVALID_PARAMETER        = -0x01, /**< Invalid function parameter */
	WAE_ERROR_PERMISSION_DENIED        = -0x02, /**< Permission denied */
	WAE_ERROR_NO_KEY                   = -0x03, /**< No key */
	WAE_ERROR_KEY_EXISTS               = -0x04, /**< key already exists*/
	WAE_ERROR_KEY_MANAGER              = -0x05, /**< key-manager internal error */
	WAE_ERROR_CRYPTO                   = -0x06, /**< failed in crypto operation */
	WAE_ERROR_MEMORY                   = -0x07, /**< failed to allocate memory */
	WAE_ERROR_FILE                     = -0x08, /**< failed to read or write a file*/
	WAE_ERROR_UNKNOWN                  = -0x09  /** < Unknown error */
} wae_error_e;

/**
 * @brief Application Type.
 * @since_tizen 3.0
 */
typedef enum {
	WAE_DOWNLOADED_NORMAL_APP = 0, /**< Downloaded Normal Application*/
	WAE_DOWNLOADED_GLOBAL_APP = 1, /**< Downloaded Global Application*/
	WAE_PRELOADED_APP         = 2  /**< Preloaded Application*/
} wae_app_type_e;

/**
 * @brief Encrypts web application data with internal key(APP DEK: Application Data Encryption Key).
 *
 * @since_tizen 3.0
 * @param[in] pPkgId   The package id of an application.
 * @param[in] appType  The application type.
 * @param[in] pData    The data block to be encrypted.
 * @param[in] dataLen  The length of the data block.
 * @param[out] ppEncryptedData The data block contaning encrypted data block. Memory allocated for ppEncryptedData. Has to be freed by free() function.
 * @param[out] pEncDataLen The length of the encrypted data block.
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_CRYPTO              failed in crypto operation
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_decrypt_web_application()
 */
int wae_encrypt_web_application(const char *pPkgId, wae_app_type_e appType, const unsigned char *pData, size_t dataLen, unsigned char **ppEncryptedData, size_t *pEncDataLen);

/**
 * @brief Encrypts web application data with internal key.
 *
 * @since_tizen 3.0
 * @param[in] pPkgId   The package id of an application.
 * @param[in] appType  The application type.
 * @param[in] pData    The data block to be decrypted.
 * @param[in] dataLen  The length of the data block.
 * @param[out] ppDecryptedData Data block contaning decrypted data block. Memory allocated for ppEncryptedData. Has to be freed by free() function.
 * @param[out] pDecDataLen The length of the decrypted data block.
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_CRYPTO              failed in crypto operation
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_encrypt_web_application()
 */
int wae_decrypt_web_application(const char *pPkgId, wae_app_type_e appType, const unsigned char *pData, size_t dataLen, unsigned char **ppDecryptedData, size_t *pDecDataLen);

/**
 * @brief Remove a APP DEK(Application Data Encryption Key) used for encrytpion and decryption of a web application.
 *
 * @since_tizen 3.0
 * @param[in] pPkgId   The package id of an application.
 * @param[in] appType  The application type.
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 */
int wae_remove_app_dek(const char *pPkgId, wae_app_type_e appType);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __WEB_APP_ENC__ */
