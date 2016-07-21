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

#include "decrypt_migrated_wgt.h"
#include "key_handler.h"
#include "crypto_service.h"
#include "types.h"
#include "wae_log.h"

int _wae_encrypt_downloaded_web_application(
		const char *pkg_id, wae_app_type_e app_type,
		const unsigned char *data, size_t data_len,
		unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	if (pkg_id == NULL || data == NULL || data_len == 0 || pencrypted_data == NULL ||
			pencrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	const crypto_element_s *e = NULL;
	int ret = get_app_ce(pkg_id, app_type, false, &e);

	if (ret == WAE_ERROR_NO_KEY)
		ret = create_app_ce(pkg_id, app_type, &e);

	if (ret != WAE_ERROR_NONE)
		return ret;

	raw_buffer_s _data;
	_data.buf = (unsigned char *)data;
	_data.size = data_len;

	raw_buffer_s *_encrypted_data = NULL;
	ret = encrypt_aes_cbc(e, &_data, &_encrypted_data);
	if (ret != WAE_ERROR_NONE)
		return ret;

	*pencrypted_data = _encrypted_data->buf;
	*pencrypted_data_len = _encrypted_data->size;

	free(_encrypted_data);

	return WAE_ERROR_NONE;
}

int _wae_decrypt_downloaded_web_application(const char *pkg_id, wae_app_type_e app_type,
		const unsigned char *data, size_t data_len,
		unsigned char **pdecrypted_data, size_t *pdecrypted_data_len)
{
	if (pkg_id == NULL || data == NULL || data_len == 0 || pdecrypted_data == NULL ||
			pdecrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	raw_buffer_s _data;
	_data.buf = (unsigned char *)data;
	_data.size = data_len;

	const crypto_element_s *ce = NULL;
	int ret = get_app_ce(pkg_id, app_type, true, &ce);

	if (ret != WAE_ERROR_NONE)
		return ret;

	raw_buffer_s *_decrypted_data = NULL;
	if (ce->is_migrated_app)
		ret = decrypt_by_old_ss_algo(ce, &_data, &_decrypted_data);
	else
		ret = decrypt_aes_cbc(ce, &_data, &_decrypted_data);

	if (ret != WAE_ERROR_NONE)
		return ret;

	*pdecrypted_data = _decrypted_data->buf;
	*pdecrypted_data_len = _decrypted_data->size;

	free(_decrypted_data);

	return WAE_ERROR_NONE;
}

int _wae_encrypt_preloaded_web_application(const char *pkg_id,
		const unsigned char *data, size_t data_len,
		unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	if (pkg_id == NULL || data == NULL || data_len == 0 || pencrypted_data == NULL ||
			pencrypted_data_len == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	const crypto_element_s *e = NULL;
	int ret = get_preloaded_app_ce(pkg_id, &e);

	if (ret == WAE_ERROR_NO_KEY)
		ret = create_preloaded_app_ce(pkg_id, &e);

	if (ret != WAE_ERROR_NONE)
		return ret;

	raw_buffer_s _data;
	_data.buf = (unsigned char *)data;
	_data.size = data_len;

	raw_buffer_s *_encrypted_data = NULL;
	ret = encrypt_aes_cbc(e, &_data, &_encrypted_data);

	if (ret != WAE_ERROR_NONE)
		return ret;

	*pencrypted_data = _encrypted_data->buf;
	*pencrypted_data_len = _encrypted_data->size;

	free(_encrypted_data);

	return WAE_ERROR_NONE;
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
	return remove_app_ce(pkg_id, app_type);
}
