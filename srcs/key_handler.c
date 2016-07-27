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
 * @file        key_handler.c
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       Key manupulatation.
 */
#include "key_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include <tzplatform_config.h>

#include "web_app_enc.h"
#include "wae_log.h"
#include "crypto_service.h"
#include "key_manager.h"
#include "decrypt_migrated_wgt.h"

#define RANDOM_FILE                 "/dev/urandom"
#define APP_DEK_KEK_PRIKEY_PASSWORD "wae_appdek_kek_1q2w3e4r"
#define APP_DEK_FILE_PFX            "WAE_APP_DEK"

#define DEK_LEN        32
#define IV_LEN         16
#define MAX_PKGID_LEN  256
#define MAX_CACHE_SIZE 100

static unsigned char AES_CBC_IV[IV_LEN] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x08, 0x39, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static crypto_element_map_s *_map;

static void deinit_lib(void) __attribute__((destructor));
static void deinit_lib(void)
{
	crypto_element_map_destroy(_map);
}

char *_create_map_key(uid_t uid, const char *pkg_id)
{
	char *key = NULL;

	int ret = asprintf(&key, "%u-%s", uid, pkg_id);

	return (ret == -1) ? NULL : key;
}

static const crypto_element_s *_get_app_ce_from_cache(const char *key)
{
	return crypto_element_map_get(_map, key);
}

static int _add_app_ce_to_cache(const char *key, crypto_element_s *ce)
{
	return crypto_element_map_add(&_map, key, ce);
}

void _remove_app_ce_from_cache(const char *key)
{
	crypto_element_map_remove(&_map, key);
}

int _get_random(raw_buffer_s *rb)
{
	if (!is_buffer_valid(rb))
		return WAE_ERROR_INVALID_PARAMETER;

	FILE *f = fopen(RANDOM_FILE, "r");

	if (f == NULL) {
		WAE_SLOGE("Failed to open random file source: %s", RANDOM_FILE);
		return WAE_ERROR_FILE;
	}

	size_t i = 0;
	int ch = 0;
	while (i < rb->size && (ch = fgetc(f) != EOF))
		rb->buf[i++] = (unsigned char)ch;

	fclose(f);

	return WAE_ERROR_NONE;
}

static const char *_get_dek_kek_pub_key_path()
{
	return tzplatform_mkpath4(TZ_SYS_SHARE, "wae", "app_dek", "WAE_APPDEK_KEK_PublicKey.pem");
}

static const char *_get_dek_kek_pri_key_path()
{
	return tzplatform_mkpath4(TZ_SYS_SHARE, "wae", "app_dek", "WAE_APPDEK_KEK_PrivateKey.pem");
}

static const char *_get_dek_store_path()
{
	return tzplatform_mkpath3(TZ_SYS_SHARE, "wae", "app_dek");
}

static int _write_to_file(const char *path, const raw_buffer_s *data)
{
	if (path == NULL || !is_buffer_valid(data))
		return WAE_ERROR_INVALID_PARAMETER;

	FILE *f = fopen(path, "w");

	if (f == NULL) {
		WAE_SLOGE("Failed to open a file(%s)", path);
		return WAE_ERROR_FILE;
	}

	int write_len = fwrite(data->buf, 1, data->size, f);

	fclose(f);

	if (write_len != (int)data->size) {
		WAE_SLOGE("Failed to write a file(%s)", path);
		return WAE_ERROR_FILE;
	}

	return WAE_ERROR_NONE;
}

static int _read_from_file(const char *path, raw_buffer_s **pdata)
{
	int ret = WAE_ERROR_NONE;
	raw_buffer_s *data = NULL;
	int ch = 0;
	int i = 0;

	FILE *f = fopen(path, "r");

	if (f == NULL) {
		WAE_SLOGE("Failed to open a file. file=%s", path);
		return WAE_ERROR_FILE;
	}

	fseek(f, 0, SEEK_END); // move to the end of a file
	int file_len = ftell(f);

	if (file_len <= 0) {
		WAE_SLOGE("Failed to get file size by ftell. ret: %d", file_len);
		ret = WAE_ERROR_FILE;
		goto error;
	}

	fseek(f, 0, SEEK_SET); // move to the start of a file

	data = buffer_create(file_len);
	if (data == NULL) {
		WAE_SLOGE("Failed to allocate memory for encrypted_dek");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	while ((ch = fgetc(f)) != EOF)
		data->buf[i++] = (char)ch;

	*pdata = data;

error:
	fclose(f);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(data);

	return ret;
}

int _get_preloaded_app_dek_file_path(const char *pkg_id, size_t size, char *path)
{
	int ret = snprintf(path, size, "%s/%s_%s.adek",
				   _get_dek_store_path(), APP_DEK_FILE_PFX, pkg_id);

	if (ret < 0)
		return WAE_ERROR_INVALID_PARAMETER; /* buffer size too small */

	return WAE_ERROR_NONE;
}

static int _extract_pkg_id_from_file_name(const char *file_name, char *pkg_id)
{
	char *start = strstr(file_name, APP_DEK_FILE_PFX);

	if (start == NULL) {
		WAE_SLOGE("WAE: Fail to extract pkgid from APP_DEK file. file_name=%s", file_name);
		return WAE_ERROR_FILE;
	}

	start = start + strlen(APP_DEK_FILE_PFX) + 1;
	char *end = strstr(file_name, ".adek");

	if (start == NULL) {
		WAE_SLOGE("WAE: Fail to extract pkgid from APP_DEK file. file_name=%s", file_name);
		return WAE_ERROR_FILE;
	}

	strncpy(pkg_id, start, end - start);
	pkg_id[end - start] = 0; //terminate string

	return WAE_ERROR_NONE;
}

int _read_encrypted_app_dek_from_file(const char *pkg_id, raw_buffer_s **pencrypted)
{
	char path[MAX_PATH_LEN] = {0,};
	_get_preloaded_app_dek_file_path(pkg_id, sizeof(path), path);
	return _read_from_file(path, pencrypted);
}

int _write_encrypted_app_dek_to_file(const char *pkg_id, const raw_buffer_s *encrypted)
{
	char path[MAX_PATH_LEN] = {0,};
	_get_preloaded_app_dek_file_path(pkg_id, sizeof(path), path);
	return _write_to_file(path, encrypted);
}

int get_app_ce(uid_t uid, const char *pkg_id, wae_app_type_e app_type,
			   bool create_for_migrated_app, const crypto_element_s **pce)
{
	if (pkg_id == NULL || pce == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	if (uid == 0 && app_type == WAE_DOWNLOADED_NORMAL_APP)
		return WAE_ERROR_INVALID_PARAMETER;

	const char *key = NULL;
	char *_key_per_user = NULL;

	if (app_type == WAE_DOWNLOADED_NORMAL_APP) {
		_key_per_user = _create_map_key(uid, pkg_id);
		if (_key_per_user == NULL)
			return WAE_ERROR_MEMORY;

		key = _key_per_user;
	} else {
		key = pkg_id;
	}

	int ret = WAE_ERROR_NONE;
	const crypto_element_s *cached_ce = _get_app_ce_from_cache(key);
	if (cached_ce != NULL) {
		WAE_SLOGD("cache hit of app ce for key(%s)", key);
		*pce = cached_ce;
		goto finish;
	}

	WAE_SLOGD("cache miss of app ce for key(%s)", key);

	crypto_element_s *ce = NULL;
	ret = get_from_key_manager(key, app_type, &ce);

	if (create_for_migrated_app &&
			(ret == WAE_ERROR_NO_KEY && app_type == WAE_DOWNLOADED_GLOBAL_APP)) {
		WAE_SLOGI("No dek found for key(%s)! It should be migrated app.", key);

		if ((ret = get_old_ss_crypto_element(key, &ce)) != WAE_ERROR_NONE)
			goto finish;

		// (k.tak) disable to save ce to key-maanger for migrated app because of permission issue.
		//ret = save_to_key_manager(key, pkg_id, app_type, ce);
		//if (ret != WAE_ERROR_NONE) {
		//	WAE_SLOGW("Failed to save migrated app ce to key-manager with ret(%d). "
		//			  "Ignore this error because we can create ce later again.", ret);
		//	ret = WAE_ERROR_NONE;
		//}
	} else if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to get crypto element from key-manager. key(%s) ret(%d)",
				  key, ret);
		goto finish;
	}

	ret = _add_app_ce_to_cache(key, ce);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to add ce to cache for key(%s) ret(%d)", key, ret);
		goto finish;
	}

	*pce = ce;

	WAE_SLOGD("Successfully get ce! key(%s)", key);

finish:
	free(_key_per_user);

	if (ret != WAE_ERROR_NONE)
		crypto_element_destroy(ce);

	return ret;
}

int create_app_ce(uid_t uid, const char *pkg_id, wae_app_type_e app_type,
				  const crypto_element_s **pce)
{
	raw_buffer_s *dek = buffer_create(DEK_LEN);
	raw_buffer_s *iv = buffer_create(IV_LEN);
	crypto_element_s *ce = crypto_element_create(dek, iv);

	int ret = WAE_ERROR_NONE;
	const char *key = NULL;
	char *_key_per_user = NULL;

	if (ce == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	if (app_type == WAE_DOWNLOADED_NORMAL_APP) {
		_key_per_user = _create_map_key(uid, pkg_id);
		if (_key_per_user == NULL) {
			ret = WAE_ERROR_MEMORY;
			goto error;
		}

		key = _key_per_user;
	} else {
		key = pkg_id;
	}

	memcpy(ce->iv->buf, AES_CBC_IV, ce->iv->size);

	ret = _get_random(dek);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to get random for dek. key(%s) ret(%d)", key, ret);
		goto error;
	}

	ret = save_to_key_manager(key, pkg_id, app_type, ce);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to save ce to key-manager. key(%s) app_type(%d) ret(%d)",
				  key, app_type, ret);
		goto error;
	}

	ret = _add_app_ce_to_cache(key, ce);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to add ce to cache for key(%s) ret(%d)", key, ret);
		goto error;
	}

	*pce = ce;

	WAE_SLOGI("Success to create dek/iv and store it in key-manager. key(%s)", key);

error:
	if (ret != WAE_ERROR_NONE) {
		if (ce == NULL) {
			buffer_destroy(dek);
			buffer_destroy(iv);
		} else {
			crypto_element_destroy(ce);
		}
	}

	free(_key_per_user);

	return ret;
}

int get_preloaded_app_ce(const char *pkg_id, const crypto_element_s **pce)
{
	const crypto_element_s *cached_ce = _get_app_ce_from_cache(pkg_id);

	if (cached_ce == NULL) {
		WAE_SLOGE("WAE: Fail to get APP_DEK from cache for preloaded app");
		return WAE_ERROR_NO_KEY;
	}

	*pce = cached_ce;

	return WAE_ERROR_NONE;
}

int create_preloaded_app_ce(const char *pkg_id, const crypto_element_s **pce)
{
	raw_buffer_s *encrypted_app_dek = NULL;
	raw_buffer_s *pubkey = NULL;
	raw_buffer_s *dek = buffer_create(DEK_LEN);
	raw_buffer_s *iv = buffer_create(sizeof(AES_CBC_IV));
	crypto_element_s *ce = crypto_element_create(dek, iv);

	int ret = WAE_ERROR_NONE;

	if (dek == NULL || iv == NULL || ce == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	ret = _get_random(dek);

	if (ret != WAE_ERROR_NONE)
		goto error;

	// copy default iv for preloaded app
	memcpy(iv->buf, AES_CBC_IV, sizeof(AES_CBC_IV));

	ret = _read_from_file(_get_dek_kek_pub_key_path(), &pubkey);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to read APP_DEK_KEK Public Key");
		goto error;
	}

	ret = encrypt_app_dek(pubkey, dek, &encrypted_app_dek);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to encrypt APP_DEK with APP_DEK_KEK");
		goto error;
	}

	// write APP_DEK in a file
	ret = _write_encrypted_app_dek_to_file(pkg_id, encrypted_app_dek);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to write encrypted dek to file. pkg_id(%s)", pkg_id);
		goto error;
	}

	// store APP_DEK in cache
	_add_app_ce_to_cache(pkg_id, ce);
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Failed to add ce to cache for pkg_id(%s) ret(%d)", pkg_id, ret);
		goto error;
	}

	*pce = ce;

	WAE_SLOGI("Success to create preleaded dek and write it in initial value file. "
			  "pkg_id(%s)", pkg_id);

error:
	buffer_destroy(encrypted_app_dek);
	buffer_destroy(pubkey);

	if (ret != WAE_ERROR_NONE) {
		if (ce) {
			crypto_element_destroy(ce);
		} else {
			buffer_destroy(dek);
			buffer_destroy(iv);
		}
	}

	return ret;
}

int _get_app_dek_kek(raw_buffer_s **pdek_kek)
{
#if 0
	return get_dek_kek_from_key_manager(pdek_kek);
#else
	return _read_from_file(_get_dek_kek_pri_key_path(), pdek_kek);
#endif
}

int load_preloaded_app_deks(bool reload)
{
	int ret = WAE_ERROR_NONE;

	char pkg_id[MAX_PKGID_LEN] = {0, };

	char file_path_buff[MAX_PATH_LEN];
	raw_buffer_s *encrypted_dek = NULL;
	raw_buffer_s *dek = NULL;
	raw_buffer_s *iv = NULL;
	raw_buffer_s *prikey = NULL;
	crypto_element_s *ce = NULL;

	int error_during_loading = 0;

	if (!reload) {
		// check if all deks were already loaded into key-manager.
		ret = is_app_deks_loaded_in_key_manager();

		if (ret == WAE_ERROR_NONE)
			return ret;
	}

	ret = _get_app_dek_kek(&prikey);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Fail to get APP_DEK_KEK Private Key");
		return ret;
	}

	DIR *dir = opendir(_get_dek_store_path());

	if (dir == NULL) {
		WAE_SLOGE("Fail to open dir. dir=%s", _get_dek_store_path());
		return WAE_ERROR_FILE;
	}

	struct dirent entry;
	struct dirent *result = NULL;

	while (true) {
		int error = readdir_r(dir, &entry, &result);

		if (error != 0) {
			ret = WAE_ERROR_FILE;
			goto error;
		}

		// readdir_r returns NULL in *result if the end
		// of the directory stream is reached
		if (result == NULL)
			break;

		// regular file && start with KEY_MANAGER_INITIAL_VALUE_FILE_PFX
		if (entry.d_type != DT_REG || strstr(entry.d_name, APP_DEK_FILE_PFX) == NULL)
			continue;

		ret = snprintf(file_path_buff, sizeof(file_path_buff), "%s/%s",
					   _get_dek_store_path(), entry.d_name);

		if (ret < 0) {
			WAE_SLOGE("Failed to make file path by snprintf.");
			ret = WAE_ERROR_INVALID_PARAMETER; /* buffer size too small */
			goto error;
		}

		ret = _extract_pkg_id_from_file_name(entry.d_name, pkg_id);

		if (ret != WAE_ERROR_NONE) {
			WAE_SLOGW("Failed to extract pkgid from file. It will be ignored. file=%s",
					  file_path_buff);
			continue;
		}

		ret = _read_from_file(file_path_buff, &encrypted_dek);

		if (ret != WAE_ERROR_NONE || encrypted_dek == NULL) {
			++error_during_loading;
			WAE_SLOGW("Failed to read file. It will be ignored. file=%s", file_path_buff);
			continue;
		}

		ret = decrypt_app_dek(prikey, APP_DEK_KEK_PRIKEY_PASSWORD, encrypted_dek, &dek);

		buffer_destroy(encrypted_dek);
		encrypted_dek = NULL;

		if (ret != WAE_ERROR_NONE || dek == NULL) {
			++error_during_loading;
			WAE_SLOGW("Failed to decrypt dek. It will be ignored. file=%s",
					  file_path_buff);
			continue;
		}
		iv = buffer_create(IV_LEN);
		if (iv == NULL) {
			++error_during_loading;
			buffer_destroy(dek);
			dek = NULL;
			continue;
		}

		memcpy(iv->buf, AES_CBC_IV, iv->size);

		ce = crypto_element_create(dek, iv);
		if (ce == NULL) {
			++error_during_loading;
			buffer_destroy(iv);
			iv = NULL;
			buffer_destroy(dek);
			dek = NULL;
			continue;
		}

		ret = save_to_key_manager(pkg_id, pkg_id, WAE_PRELOADED_APP, ce);

		if (ret == WAE_ERROR_KEY_EXISTS) {
			WAE_SLOGI("Key Manager already has dek. It will be ignored. file=%s",
					  file_path_buff);
		} else if (ret != WAE_ERROR_NONE) {
			++error_during_loading;
			WAE_SLOGW("Fail to add APP DEK to key-manager. file=%s", file_path_buff);
		}

		crypto_element_destroy(ce);
		ce = NULL;
	}

	ret = set_app_deks_loaded_to_key_manager();

error:
	if (ret != WAE_ERROR_NONE) {
		if (ce) {
			crypto_element_destroy(ce);
		} else {
			buffer_destroy(dek);
			buffer_destroy(iv);
		}
	}

	buffer_destroy(prikey);
	closedir(dir);

	return ret;
}

int remove_app_ce(uid_t uid, const char *pkg_id, wae_app_type_e app_type)
{
	if (uid == 0 && app_type == WAE_DOWNLOADED_NORMAL_APP)
		return WAE_ERROR_INVALID_PARAMETER;

	const char *key = NULL;
	char *_key_per_user = NULL;

	if (app_type == WAE_DOWNLOADED_NORMAL_APP) {
		_key_per_user = _create_map_key(uid, pkg_id);
		if (_key_per_user == NULL)
			return WAE_ERROR_MEMORY;

		key = _key_per_user;
	} else {
		key = pkg_id;
	}

	int ret = remove_from_key_manager(key, app_type);

	if (ret != WAE_ERROR_NONE)
		WAE_SLOGE("Failed to remove app ce for key(%s) ret(%d)", key, ret);
	else
		WAE_SLOGI("Success to remove app ce for key(%s)", key);

	_remove_app_ce_from_cache(key);

	free(_key_per_user);

	return ret;
}
