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
 * @file        key_manager.c
 * @author      Kyungwook Tak
 * @version     1.0
 * @brief       Serialize/deserialize crypto element and save/get to key-manager
 */
#include "key_manager.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ckmc/ckmc-manager.h>

#include "web_app_enc.h"
#include "wae_log.h"

#define MAX_ALIAS_LEN               256
#define APP_DEK_ALIAS_PFX           "APP_DEK_"
#define APP_DEK_LOADING_DONE_ALIAS  "APP_DEKS_LOADING_FINISHED"
#define APP_DEK_KEK_ALIAS           "WAE_APP_DEK_KEK"

static int _to_wae_error(int key_manager_error)
{
	switch (key_manager_error) {
	case CKMC_ERROR_NONE:
		return WAE_ERROR_NONE;

	case CKMC_ERROR_INVALID_PARAMETER:
		return WAE_ERROR_INVALID_PARAMETER;

	case CKMC_ERROR_PERMISSION_DENIED:
		return WAE_ERROR_PERMISSION_DENIED;

	case CKMC_ERROR_DB_ALIAS_UNKNOWN:
		return WAE_ERROR_NO_KEY;

	case CKMC_ERROR_DB_ALIAS_EXISTS:
		return WAE_ERROR_KEY_EXISTS;

	case CKMC_ERROR_OUT_OF_MEMORY:
		return WAE_ERROR_MEMORY;

	default:
		return WAE_ERROR_KEY_MANAGER;
	}
}

static int _serialize(const crypto_element_s *ce, ckmc_raw_buffer_s **pbuf)
{
	if (!is_crypto_element_valid(ce) || pbuf == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	size_t total_len = sizeof(size_t) * 3 + ce->dek->size + ce->iv->size + sizeof(bool);

	WAE_SLOGD("(serialization) total(%d) dek(%d) iv(%d) is_migrated(%d)",
			  total_len, ce->dek->size, ce->iv->size, ce->is_migrated_app);

	unsigned char *_buf = (unsigned char *)malloc(total_len);
	if (_buf == NULL)
		return WAE_ERROR_MEMORY;

	ckmc_raw_buffer_s *buf = NULL;
	int ret = _to_wae_error(ckmc_buffer_new(_buf, total_len, &buf));

	free(_buf);

	if (ret != WAE_ERROR_NONE)
		return ret;

	size_t pos = 0;
	memcpy(buf->data, &total_len, sizeof(size_t));
	pos += sizeof(size_t);
	memcpy(buf->data + pos, &ce->dek->size, sizeof(size_t));
	pos += sizeof(size_t);
	memcpy(buf->data + pos, ce->dek->buf, ce->dek->size);
	pos += ce->dek->size;
	memcpy(buf->data + pos, &ce->iv->size, sizeof(size_t));
	pos += sizeof(size_t);
	memcpy(buf->data + pos, ce->iv->buf, ce->iv->size);
	pos += ce->iv->size;
	memcpy(buf->data + pos, &ce->is_migrated_app, sizeof(bool));
	pos += sizeof(bool);

	if (total_len != pos) {
		WAE_SLOGE("(serialization) total len(%d) and actualy written byte(%d) "
				  "isn't matched!", total_len, pos);
		ckmc_buffer_free(buf);
		return WAE_ERROR_UNKNOWN;
	}

	*pbuf = buf;

	WAE_SLOGD("(serialization) success!");

	return WAE_ERROR_NONE;
}

static int _deserialize(const ckmc_raw_buffer_s *buf, crypto_element_s **pce)
{
	if (buf == NULL || buf->data == NULL || buf->size == 0 || pce == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	size_t dek_size = 0;
	size_t iv_size = 0;
	bool is_migrated_app = false;
	size_t pos = 0;
	size_t total_len = 0;
	crypto_element_s *ce = NULL;

	memcpy(&total_len, buf->data, sizeof(size_t));
	pos += sizeof(size_t);

	if (buf->size != total_len) {
		WAE_SLOGE("(deserialization) total len(%d) and actualy written byte(%d) "
				  "isn't matched!", total_len, buf->size);
		return WAE_ERROR_UNKNOWN;
	}

	// deserialize dek size
	memcpy(&dek_size, buf->data + pos, sizeof(size_t));
	pos += sizeof(size_t);

	raw_buffer_s *dek = buffer_create(dek_size);
	if (dek == NULL)
		return WAE_ERROR_MEMORY;

	// deserialize dek
	memcpy(dek->buf, buf->data + pos, dek->size);
	pos += dek->size;

	// deserialize iv size
	memcpy(&iv_size, buf->data + pos, sizeof(size_t));
	pos += sizeof(size_t);

	raw_buffer_s *iv = buffer_create(iv_size);
	int ret = WAE_ERROR_NONE;
	if (iv == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	// deserialize iv
	memcpy(iv->buf, buf->data + pos, iv->size);
	pos += iv->size;

	// deserialize is_migrated_app
	memcpy(&is_migrated_app, buf->data + pos, sizeof(bool));
	pos += sizeof(bool);

	WAE_SLOGD("(deserialization) total(%d) dek(%d) iv(%d) is_migrated(%d)",
			  total_len, dek_size, iv_size, is_migrated_app);

	if (pos != buf->size) {
		WAE_SLOGE("(deserialization) raw buffer remained after deserializatation done!");
		ret = WAE_ERROR_UNKNOWN;
		goto error;
	}

	ce = crypto_element_create(dek, iv);
	if (ce == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	ce->is_migrated_app = is_migrated_app;

	*pce = ce;

	WAE_SLOGD("(deserialization) success!");

	return WAE_ERROR_NONE;

error:
	buffer_destroy(dek);
	buffer_destroy(iv);

	return ret;
}

static void _get_alias(const char *name, UNUSED wae_app_type_e type, UNUSED bool forSave,
					   char *alias, size_t buff_len)
{
	snprintf(alias, buff_len, "%s%s%s%s",
			 ckmc_owner_id_system,
			 ckmc_owner_id_separator,
			 APP_DEK_ALIAS_PFX,
			 name);
}

static void _get_dek_loading_done_alias(char *alias, size_t buff_len)
{
	snprintf(alias, buff_len, "%s%s%s",
			 ckmc_owner_id_system,
			 ckmc_owner_id_separator,
			 APP_DEK_LOADING_DONE_ALIAS);
}

bool is_app_deks_loaded_in_key_manager()
{
	char alias[MAX_ALIAS_LEN] = {0, };

	_get_dek_loading_done_alias(alias, sizeof(alias));

	ckmc_raw_buffer_s *buf = NULL;
	int ret = _to_wae_error(ckmc_get_data(alias, NULL, &buf));

	ckmc_buffer_free(buf);

	switch (ret) {
	case WAE_ERROR_NONE:
		return true;
	case WAE_ERROR_NO_KEY:
		WAE_SLOGI("app dek loading isn't done yet");
		return false;
	default:
		WAE_SLOGE("Failed to get dek loading flag data from key-manager. ret(%d)", ret);
		return false;
	}
}

int set_app_deks_loaded_to_key_manager()
{
	unsigned char dummy_data[1] = {0};
	ckmc_raw_buffer_s buf;
	buf.data = dummy_data;
	buf.size = sizeof(dummy_data);

	ckmc_policy_s policy;
	policy.password = NULL;
	policy.extractable = true;

	char alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_loading_done_alias(alias, sizeof(alias));

	int ret = _to_wae_error(ckmc_save_data(alias, buf, policy));
	if (ret == WAE_ERROR_KEY_EXISTS)
		ret = WAE_ERROR_NONE;

	return ret;
}

int clear_app_deks_loaded_from_key_manager()
{
	char alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_loading_done_alias(alias, sizeof(alias));

	return _to_wae_error(ckmc_remove_alias(alias));
}

int save_to_key_manager(const char *name, const char *pkg_id, wae_app_type_e type,
						const crypto_element_s *ce)
{
	char alias[MAX_ALIAS_LEN] = {0, };

	_get_alias(name, type, true, alias, sizeof(alias));

	ckmc_raw_buffer_s *buf = NULL;
	int ret = _serialize(ce, &buf);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to serialize crypto element of name(%s)", name);
		return ret;
	}

	ckmc_policy_s policy;
	policy.password = NULL;
	policy.extractable = true;

	ret = _to_wae_error(ckmc_save_data(alias, *buf, policy));

	ckmc_buffer_free(buf);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to add crypto element to ckm: name(%s) alias(%s) ret(%d)",
				  name, alias, ret);
		return ret;
	}

	ret = _to_wae_error(ckmc_set_permission(alias, pkg_id, CKMC_PERMISSION_READ));
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to set perm of crypto element: pkg_id(%s) alias(%s) ret(%d)",
				  pkg_id, alias, ret);

		ckmc_remove_alias(alias); // rollback
		return ret;
	}

	WAE_SLOGI("Success to save crypto element to key-manager. name(%s)", name);

	return WAE_ERROR_NONE;
}

int get_from_key_manager(const char *name, wae_app_type_e type, crypto_element_s **pce)
{
	if (name == NULL || pce == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	char alias[MAX_ALIAS_LEN] = {0, };

	_get_alias(name, type, false, alias, sizeof(alias));

	ckmc_raw_buffer_s *buf = NULL;
	int ret = _to_wae_error(ckmc_get_data(alias, NULL, &buf));
	if (ret != WAE_ERROR_NONE)
		return ret;

	ret = _deserialize(buf, pce);

	ckmc_buffer_free(buf);

	return ret;
}

int remove_from_key_manager(const char *name, wae_app_type_e type)
{
	char alias[MAX_ALIAS_LEN] = {0, };

	_get_alias(name, type, true, alias, sizeof(alias));

	return _to_wae_error(ckmc_remove_alias(alias));
}

static void _get_dek_kek_alias(char *alias, size_t buff_len)
{
	snprintf(alias, buff_len, "%s%s%s",
			 ckmc_owner_id_system,
			 ckmc_owner_id_separator,
			 APP_DEK_KEK_ALIAS);
}

int get_dek_kek_from_key_manager(raw_buffer_s **pdek_kek)
{
	if (pdek_kek == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	ckmc_raw_buffer_s *buf = NULL;

	char alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_kek_alias(alias, sizeof(alias));

	int ret = _to_wae_error(ckmc_get_data(alias, NULL, &buf));
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to get dek kek from key-manager. alias(%s) ret(%d)",
				  alias, ret);
		return ret;
	}

	raw_buffer_s *dek_kek = buffer_create(buf->size);
	if (dek_kek == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}
	memcpy(dek_kek->buf, buf->data, dek_kek->size);

	*pdek_kek = dek_kek;

	WAE_SLOGI("Success to get dek kek from key-manager.");

error:
	ckmc_buffer_free(buf);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(dek_kek);

	return ret;
}
