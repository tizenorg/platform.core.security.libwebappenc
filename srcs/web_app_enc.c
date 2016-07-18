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
 * @file        web_app_enc.c
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       provides fucntions for encryption and decryption of web application.
 */
#include "web_app_enc.h"

#include <stdlib.h>

#include "ss_key_generator.h"
#include "key_handler.h"
#include "crypto_service.h"
#include "wae_log.h"

int _wae_encrypt_downloaded_web_application(
		const char *pkg_id, wae_app_type_e app_type,
		const unsigned char *data, size_t data_len,
		unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	if (pkg_id == NULL || data == NULL || data_len == 0 || pencrypted_data == NULL ||
			pencrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	// get APP_DEK.
	//   if not exists, create APP_DEK
	unsigned char *dek = NULL;
	size_t dek_len = -1;
	int ret = get_app_dek(pkg_id, app_type, &dek, &dek_len);

	if (ret == WAE_ERROR_NO_KEY)
		ret = create_app_dek(pkg_id, app_type, &dek, &dek_len);

	if (ret != WAE_ERROR_NONE)
		goto error;

	// encrypt
	ret = encrypt_aes_cbc(dek, dek_len, data, data_len, pencrypted_data, pencrypted_data_len);

error:
	free(dek);

	return ret;
}

int _wae_decrypt_downloaded_web_application(const char *pkg_id, wae_app_type_e app_type,
		const unsigned char *data, size_t data_len,
		unsigned char **pdecrypted_data, size_t *pdecrypted_data_len)
{

	if (pkg_id == NULL || data == NULL || data_len == 0 || pdecrypted_data == NULL ||
			pdecrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	unsigned char *dek = NULL;
	size_t dek_len = -1;
	int ret = get_app_dek(pkg_id, app_type, &dek, &dek_len);

	if (ret != WAE_ERROR_NONE)
		goto error;

	// decrypt
	ret = decrypt_aes_cbc(dek, dek_len, data, data_len, pdecrypted_data, pdecrypted_data_len);

error:
	free(dek);

	return ret;
}

int _wae_encrypt_preloaded_web_application(const char *pkg_id,
		const unsigned char *data, size_t data_len,
		unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	if (pkg_id == NULL || data == NULL || data_len == 0 || pencrypted_data == NULL ||
			pencrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	unsigned char *dek = NULL;
	size_t dek_len = -1;
	int ret = get_preloaded_app_dek(pkg_id, &dek, &dek_len);

	if (ret == WAE_ERROR_NO_KEY)
		ret = create_preloaded_app_dek(pkg_id, &dek, &dek_len);

	if (ret != WAE_ERROR_NONE)
		goto error;

	// encrypt
	ret = encrypt_aes_cbc(dek, dek_len, data, data_len, pencrypted_data, pencrypted_data_len);

error:
	free(dek);

	return ret;
}

int _wae_decrypt_preloaded_web_application(const char *pkg_id, wae_app_type_e app_type,
		const unsigned char *data, size_t data_len,
		unsigned char **pdecrypted_data, size_t *pdecrypted_data_len)
{
	// same with the decryption of downloaded web application
	return _wae_decrypt_downloaded_web_application(pkg_id, app_type,
			data, data_len, pdecrypted_data, pdecrypted_data_len);
}

int wae_encrypt_web_application(const char *pkg_id, wae_app_type_e app_type,
								const unsigned char *data, size_t data_len,
								unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	if (app_type == WAE_PRELOADED_APP)
		return _wae_encrypt_preloaded_web_application(pkg_id,
				data, data_len, pencrypted_data, pencrypted_data_len);
	else
		return _wae_encrypt_downloaded_web_application(pkg_id, app_type,
				data, data_len, pencrypted_data, pencrypted_data_len);
}

int wae_decrypt_web_application(const char *pkg_id, wae_app_type_e app_type,
								const unsigned char *data, size_t data_len,
								unsigned char **pdecrypted_data, size_t *pdecrypted_data_len)
{
	if (app_type == WAE_PRELOADED_APP)
		return _wae_decrypt_preloaded_web_application(pkg_id, app_type,
				data, data_len, pdecrypted_data, pdecrypted_data_len);
	else
		return _wae_decrypt_downloaded_web_application(pkg_id, app_type,
				data, data_len, pdecrypted_data, pdecrypted_data_len);
}


int wae_remove_app_dek(const char *pkg_id, wae_app_type_e app_type)
{
	return remove_app_dek(pkg_id, app_type);
}
