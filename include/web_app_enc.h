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
 * @version 2.0
 * @brief   APIs of WEB_APP_ENC module.
*/
#ifndef __WEB_APP_ENC__
#define __WEB_APP_ENC__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

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
 * @brief Encrypts web application data
 *
 * @since_tizen 3.0
 * @param[in] uid                  User id of the application being encrypted
 * @param[in] pkg_id               The package id of an application
 * @param[in] data                 The data block to be encrypted
 * @param[in] data_len             The length of @a data
 * @param[out] pencrypted_data     The encrypted data block which must be freed by free()
 * @param[out] pencrypted_data_len The length of data pointed by @a pencrypted_data
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
 * @see wae_remove_app_dek()
 */
int wae_encrypt_web_application(uid_t uid, const char *pkg_id,
								const unsigned char *data, size_t data_len,
								unsigned char **pencrypted_data, size_t *pencrypted_data_len);

/**
 * @brief Encrypts global web application data
 *
 * @since_tizen 3.0
 * @param[in] pkg_id               The package id of an application
 * @param[in] is_preloaded         Whether the package is preloaded or not
 * @param[in] data                 The data block to be encrypted
 * @param[in] data_len             The length of @a data
 * @param[out] pencrypted_data     The encrypted data block which must be freed by free()
 * @param[out] pencrypted_data_len The length of data pointed by @a pencrypted_data
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_CRYPTO              failed in crypto operation
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_decrypt_global_web_application()
 * @see wae_remove_global_app_dek()
 */
int wae_encrypt_global_web_application(const char *pkg_id, bool is_preloaded,
									   const unsigned char *data, size_t data_len,
									   unsigned char **pencrypted_data, size_t *pencrypted_data_len);

/**
 * @brief Decrypts web application data.
 *
 * @since_tizen 3.0
 * @param[in] uid                  User id of the application being decrypted
 * @param[in] pkg_id               The package id of an application
 * @param[in] data                 The data block to be decrypted
 * @param[in] data_len             The length of @a data
 * @param[out] pdecrypted_data     The decrypted data block which must be freed by free()
 * @param[out] pdecrypted_data_len The length of data pointed by @a pdecrypted_data
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
 * @see wae_remove_app_dek()
 */
int wae_decrypt_web_application(uid_t uid, const char *pkg_id,
								const unsigned char *data, size_t data_len,
								unsigned char **pdecrypted_data, size_t *pdecrypted_data_len);

/**
 * @brief Decrypts global web application data.
 *
 * @since_tizen 3.0
 * @param[in] pkg_id               The package id of an application
 * @param[in] is_preloaded         Whether the package is preloaded or not
 * @param[in] data                 The data block to be decrypted
 * @param[in] data_len             The length of @a data
 * @param[out] pdecrypted_data     The decrypted data block which must be freed by free()
 * @param[out] pdecrypted_data_len The length of data pointed by @a pdecrypted_data
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_CRYPTO              failed in crypto operation
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_encrypt_global_web_application()
 * @see wae_remove_global_app_dek()
 */
int wae_decrypt_global_web_application(const char *pkg_id, bool is_preloaded,
									   const unsigned char *data, size_t data_len,
									   unsigned char **pdecrypted_data, size_t *pdecrypted_data_len);

/**
 * @brief Remove key used for encryption the web application.
 *
 * @since_tizen 3.0
 * @param[in] uid       User id of the application being uninstalled
 * @param[in] pkg_id    The package id of an application
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_encrypt_web_application()
 * @see wae_decrypt_web_application()
 */
int wae_remove_app_dek(uid_t uid, const char *pkg_id);

/**
 * @brief Remove key used for encryption the global web application.
 *
 * @since_tizen 3.0
 * @param[in] pkg_id        The package id of an application
 * @param[in] is_preloaded  Whether the package is preloaded or not
 *
 * @return #WAE_ERROR_NONE on success, otherwise a negative error value
 * @retval #WAE_ERROR_INVALID_PARAMETER   Invalid input parameter
 * @retval #WAE_ERROR_PERMISSION_DENIED   Non-authenticated application request
 * @retval #WAE_ERROR_NO_KEY              No internal key
 * @retval #WAE_ERROR_KEY_MANAGER         key-manager internal error
 * @retval #WAE_ERROR_UNKNOWN             Failed with unknown reason
 *
 * @see wae_encrypt_global_web_application()
 * @see wae_decrypt_global_web_application()
 */
int wae_remove_global_app_dek(const char *pkg_id, bool is_preloaded);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __WEB_APP_ENC__ */
