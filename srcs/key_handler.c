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

#include <ckmc/ckmc-manager.h>
#include <tzplatform_config.h>

#include "wae_log.h"
#include "web_app_enc.h"
#include "crypto_service.h"

#define RANDOM_FILE                 "/dev/urandom"
#define APP_DEK_KEK_PRIKEY_PASSWORD "wae_appdek_kek_1q2w3e4r"
#define APP_DEK_ALIAS_PFX           "APP_DEK_"
#define APP_DEK_LOADING_DONE_ALIAS  "APP_DEKS_LOADING_FINISHED"
#define APP_DEK_FILE_PFX            "WAE_APP_DEK"
#define APP_DEK_KEK_ALIAS           "WAE_APP_DEK_KEK"

#define DEK_LEN        32
#define MAX_ALIAS_LEN  256
#define MAX_PKGID_LEN  256
#define MAX_CACHE_SIZE 100

typedef struct _dek_cache_element {
	char pkgId[MAX_PKGID_LEN];
	unsigned char dek[DEK_LEN];
} dek_cache_element;

dek_cache_element APP_DEK_CACHE[MAX_CACHE_SIZE];
int NEXT_CACHE_IDX = -1;

void _initialize_cache()
{
	NEXT_CACHE_IDX = 0;
	memset(APP_DEK_CACHE, 0, sizeof(dek_cache_element) * MAX_CACHE_SIZE);
}

const unsigned char *_get_app_dek_from_cache(const char *pkgId)
{
	if (NEXT_CACHE_IDX < 0)
		_initialize_cache();

	for (size_t i = 0; i < MAX_CACHE_SIZE; i++) {
		//WAE_SLOGI("CACHED APP_DEK[%d]=%s", i, APP_DEK_CACHE[i].pkgId);
		if (strncmp(pkgId, APP_DEK_CACHE[i].pkgId, MAX_PKGID_LEN) == 0)
			return APP_DEK_CACHE[i].dek;
	}

	return NULL;
}

void _add_app_dek_to_cache(const char *pkgId, const unsigned char *dek)
{
	if (NEXT_CACHE_IDX < 0)
		_initialize_cache();

	// if existing one has the same pkgid
	for (size_t i = 0; i < MAX_CACHE_SIZE; i++) {
		if (strncmp(pkgId, APP_DEK_CACHE[i].pkgId, MAX_PKGID_LEN) == 0) {
			memcpy(APP_DEK_CACHE[i].dek, dek, DEK_LEN);
			return;
		}
	}

	// for new pkgid
	strncpy(APP_DEK_CACHE[NEXT_CACHE_IDX].pkgId, pkgId, MAX_PKGID_LEN - 1);
	memcpy(APP_DEK_CACHE[NEXT_CACHE_IDX].dek, dek, DEK_LEN);

	++NEXT_CACHE_IDX;

	if (NEXT_CACHE_IDX >= MAX_CACHE_SIZE)
		NEXT_CACHE_IDX = 0;
}

void _remove_app_dek_from_cache(const char *pkgId)
{
	for (size_t i = 0; i < MAX_CACHE_SIZE; i++) {
		if (strncmp(pkgId, APP_DEK_CACHE[i].pkgId, MAX_PKGID_LEN) == 0) {
			memset(APP_DEK_CACHE[i].pkgId, 0, MAX_PKGID_LEN);
			return;
		}
	}

}

int _to_wae_error(int key_manager_error)
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

	default:
		return WAE_ERROR_KEY_MANAGER;
	}
}

int _get_random(size_t length, unsigned char *random)
{
	FILE *f = fopen(RANDOM_FILE, "r");

	if (f == NULL) {
		WAE_SLOGE("Failed to open random file source: %s", RANDOM_FILE);
		return WAE_ERROR_FILE;
	}

	size_t i = 0;
	int ch = 0;
	while (i < length && (ch = fgetc(f) != EOF))
		random[i++] = (unsigned char)ch;

	fclose(f);

	return WAE_ERROR_NONE;
}

void _get_alias(const char *pkgId, wae_app_type_e appType, bool forSave, char *alias, size_t buff_len)
{
	if (appType == WAE_DOWNLOADED_NORMAL_APP) {
		if (forSave) {
			snprintf(alias, buff_len, "%s%s",
					 APP_DEK_ALIAS_PFX,
					 pkgId);
		} else {
			snprintf(alias, buff_len, "%c%s%s%s%s",
					'/', INSTALLER_LABEL,
					 ckmc_owner_id_separator,
					 APP_DEK_ALIAS_PFX,
					 pkgId);
		}
	} else { // system alias
		snprintf(alias, buff_len, "%s%s%s%s",
				 ckmc_owner_id_system,
				 ckmc_owner_id_separator,
				 APP_DEK_ALIAS_PFX,
				 pkgId);
	}
}

void _get_dek_kek_alias(char *alias, size_t buff_len)
{
	snprintf(alias, buff_len, "%s%s%s",
			 ckmc_owner_id_system,
			 ckmc_owner_id_separator,
			 APP_DEK_KEK_ALIAS);
}

void _get_dek_loading_done_alias(char *alias, size_t buff_len)
{
	snprintf(alias, buff_len, "%s%s%s",
			 ckmc_owner_id_system,
			 ckmc_owner_id_separator,
			 APP_DEK_LOADING_DONE_ALIAS);
}

const char *_get_dek_kek_pub_key_path()
{
	return tzplatform_mkpath4(TZ_SYS_SHARE, "wae", "app_dek", "WAE_APPDEK_KEK_PublicKey.pem");
}

const char *_get_dek_kek_pri_key_path()
{
	return tzplatform_mkpath4(TZ_SYS_SHARE, "wae", "app_dek", "WAE_APPDEK_KEK_PrivateKey.pem");
}

const char *_get_dek_store_path()
{
	return tzplatform_mkpath3(TZ_SYS_SHARE, "wae", "app_dek");
}

int _add_dek_to_key_manager(const char *pkgId, wae_app_type_e appType, const unsigned char *dek, size_t len)
{
	int ret = WAE_ERROR_NONE;
	char alias[MAX_ALIAS_LEN] = {0, };
	ckmc_raw_buffer_s buff;
	ckmc_policy_s policy;

	buff.data = (unsigned char *)dek;
	buff.size = len;

	policy.password = NULL;
	policy.extractable = true;

	_get_alias(pkgId, appType, true, alias, sizeof(alias));

	// even if it fails to remove, ignore it.
	ckmc_remove_alias(alias);

	ret = _to_wae_error(ckmc_save_data(alias, buff, policy));
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to add APP_DEK to key-manager. pkgId=%s, alias=%s, ret=%d", pkgId, alias, ret);
		return ret;
	}

	// share app_dek for web app laucher to use app_dek
	ret = _to_wae_error(ckmc_set_permission(alias, pkgId, CKMC_PERMISSION_READ));
	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to set_permission to APP_DEK. pkgId=%s, ret=%d", pkgId, ret);
		return ret;
	}

	WAE_SLOGI("WAE: Success to add APP_DEK to key-manager. pkgId=%s, alias=%s", pkgId, alias);

	return ret;
}

int _get_preloaded_app_dek_file_path(const char *pkgId, size_t size, char *path)
{
	int ret = snprintf(path, size, "%s/%s_%s.adek",
				   _get_dek_store_path(), APP_DEK_FILE_PFX, pkgId);

	if (ret < 0)
		return WAE_ERROR_INVALID_PARAMETER; /* buffer size too small */

	return WAE_ERROR_NONE;
}

int _extract_pkg_id_from_file_name(const char *fileName, char *pkgId)
{
	char *start = strstr(fileName, APP_DEK_FILE_PFX);

	if (start == NULL) {
		WAE_SLOGE("WAE: Fail to extract pkgid from APP_DEK file. fileName=%s", fileName);
		return WAE_ERROR_FILE;
	}

	start = start + strlen(APP_DEK_FILE_PFX) + 1;
	char *end = strstr(fileName, ".adek");

	if (start == NULL) {
		WAE_SLOGE("WAE: Fail to extract pkgid from APP_DEK file. fileName=%s", fileName);
		return WAE_ERROR_FILE;
	}

	strncpy(pkgId, start, end - start);
	pkgId[end - start] = 0; //terminate string

	return WAE_ERROR_NONE;
}

int _read_encrypted_app_dek_from_file(const char *pkgId, unsigned char **encrypted_app_dek, size_t *len)
{
	char path[MAX_PATH_LEN] = {0,};
	_get_preloaded_app_dek_file_path(pkgId, sizeof(path), path);
	return _read_from_file(path, encrypted_app_dek, len);
}

int _write_encrypted_app_dek_to_file(const char *pkgId, const unsigned char *encrypted_app_dek, size_t len)
{
	char path[MAX_PATH_LEN] = {0,};
	_get_preloaded_app_dek_file_path(pkgId, sizeof(path), path);
	return _write_to_file(path, encrypted_app_dek, len);
}

int _read_from_file(const char *path, unsigned char **pData, size_t *len)
{
	int ret = WAE_ERROR_NONE;
	unsigned char *file_contents = NULL;
	int ch = 0;
	int i = 0;

	FILE *f = fopen(path, "r");

	if (f == NULL) {
		WAE_SLOGE("WAE: Fail to open a file. file=%s", path);
		return WAE_ERROR_FILE;
	}

	fseek(f, 0, SEEK_END); // move to the end of a file
	int file_len = ftell(f);

	if (file_len <= 0) {
		WAE_SLOGE("WAE: Failed to get file size by ftell. ret: %d", file_len);
		ret = WAE_ERROR_FILE;
		goto error;
	}

	fseek(f, 0, SEEK_SET); // move to the start of a file

	file_contents = (unsigned char *)malloc(file_len);

	if (file_contents == NULL) {
		WAE_SLOGE("WAE: Fail to allocate memory for encrypted_app_dek");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	memset(file_contents, 0x00, file_len);

	while ((ch = fgetc(f)) != EOF)
		file_contents[i++] = (char)ch;

	*pData = file_contents;
	*len = file_len;

error:
	if (f != NULL)
		fclose(f);

	if (ret != WAE_ERROR_NONE)
		free(file_contents);

	return ret;
}

int _write_to_file(const char *path, const unsigned char *data, size_t len)
{
	FILE *f = fopen(path, "w");

	if (f == NULL) {
		WAE_SLOGE("WAE: Fail to open a file. file=%s", path);
		return WAE_ERROR_FILE;
	}

	int write_len = fwrite(data, 1, len, f);

	fclose(f);

	if (write_len != (int)len) {
		WAE_SLOGE("WAE: Fail to write a file. file=%s", path);
		return WAE_ERROR_FILE;
	}

	return WAE_ERROR_NONE;
}

int get_app_dek(const char *pkgId, wae_app_type_e appType, unsigned char **pDek, size_t *dekLen)
{
	int ret = WAE_ERROR_NONE;

	ckmc_raw_buffer_s *dekBuffer = NULL;
	char alias[MAX_ALIAS_LEN] = {0, };

	const unsigned char *cached_dek = _get_app_dek_from_cache(pkgId);

	if (cached_dek == NULL) {
		// get APP_DEK from system database
		_get_alias(pkgId, appType, false, alias, sizeof(alias));

		ret = _to_wae_error(ckmc_get_data(alias, NULL, &dekBuffer));

		if (ret != WAE_ERROR_NONE) {
			WAE_SLOGE("Failed to get APP_DEK from key-manager. pkgId=%s, alias=%s, ret=%d",
					  pkgId, alias, ret);
			goto error;
		} else if (dekBuffer == NULL || dekBuffer->data == NULL) {
			WAE_SLOGE("key-manager success but buffer is null for getting dek of pkgId=%s",
					  pkgId);
			ret = WAE_ERROR_KEY_MANAGER;
			goto error;
		} else if (dekBuffer->size != DEK_LEN) {
			WAE_SLOGE("DEK's length which has been saved in key-manager is not valid!");
			ret = WAE_ERROR_KEY_MANAGER;
			goto error;
		}

		WAE_SLOGD("Successfully get dek from key-manager for pkgid=%s", pkgId);
		cached_dek = dekBuffer->data;
	}

	unsigned char *dek = (unsigned char *)malloc(DEK_LEN);

	if (dek == NULL) {
		WAE_SLOGE("Fail to allocate a memory");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	memcpy(dek, cached_dek, DEK_LEN);

	*pDek = dek;
	*dekLen = DEK_LEN;

	WAE_SLOGI("WAE: Success to get APP_DEK from key-manager. pkgId=%s, alias=%s",
			  pkgId, alias);

error:
	ckmc_buffer_free(dekBuffer);

	if (ret != WAE_ERROR_NONE)
		free(dek);

	return ret;
}

int create_app_dek(const char *pkgId, wae_app_type_e appType, unsigned char **pDek, size_t *dekLen)
{
	unsigned char *dek = (unsigned char *)malloc(DEK_LEN);

	if (dek == NULL)
		return WAE_ERROR_MEMORY;

	int ret = _get_random(DEK_LEN, dek);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to get random for APP_DEK. pkgId=%s, ret=%d", pkgId, ret);
		goto error;
	}

	// save app_dek in key_manager
	ret = _add_dek_to_key_manager(pkgId, appType, dek, DEK_LEN);

	if (ret != WAE_ERROR_NONE) {
		goto error;
	}

	// store APP_DEK in cache
	_add_app_dek_to_cache(pkgId, dek);

	*pDek = dek;
	*dekLen = DEK_LEN;

	WAE_SLOGI("WAE: Success to create APP_DEK and store it in key-manager. pkgId=%s", pkgId);

	return WAE_ERROR_NONE;

error:
	free(dek);

	return ret;
}

int get_preloaded_app_dek(const char *pkgId, unsigned char **pDek, size_t *dekLen)
{
	const unsigned char *cached_dek = _get_app_dek_from_cache(pkgId);

	if (cached_dek == NULL) {
		WAE_SLOGE("WAE: Fail to get APP_DEK from cache for preloaded app");
		return WAE_ERROR_NO_KEY;
	}

	unsigned char *dek = (unsigned char *)malloc(DEK_LEN);

	if (dek == NULL) {
		WAE_SLOGE("WAE: Fail to allocate memory for preloaded app dek");
		return WAE_ERROR_MEMORY;
	}

	memcpy(dek, cached_dek, DEK_LEN);

	*pDek = dek;
	*dekLen = DEK_LEN;

	return WAE_ERROR_NONE;
}

int create_preloaded_app_dek(const char *pkgId, unsigned char **pDek, size_t *dekLen)
{
	unsigned char *encrypted_app_dek = NULL;
	size_t encrypted_app_dek_len = 0;
	unsigned char *pubKey = NULL;
	size_t pubKeyLen = 0;

	// create APP_DEK
	unsigned char *dek = (unsigned char *)malloc(DEK_LEN);

	if (dek == NULL)
		return WAE_ERROR_MEMORY;

	int ret = _get_random(DEK_LEN, dek);

	if (ret != WAE_ERROR_NONE)
		goto error;

	// encrypt APP_DEK with APP_DEK_KEK
	ret = _read_from_file(_get_dek_kek_pub_key_path(), &pubKey, &pubKeyLen);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to read APP_DEK_KEK Public Key");
		goto error;
	}

	ret = encrypt_app_dek(pubKey, pubKeyLen, dek, DEK_LEN, &encrypted_app_dek, &encrypted_app_dek_len);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to encrypt APP_DEK with APP_DEK_KEK");
		goto error;
	}

	// write APP_DEK in a file
	ret = _write_encrypted_app_dek_to_file(pkgId, encrypted_app_dek, encrypted_app_dek_len);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to write encrypted APP_DEK. pkgId=%s", pkgId);
		goto error;
	}

	// store APP_DEK in cache
	_add_app_dek_to_cache(pkgId, dek);

	*pDek = dek;
	*dekLen = DEK_LEN;
	WAE_SLOGI("WAE: Success to create preleaded APP_DEK and write it in initail value file. pkgId=%s", pkgId);

error:
	free(pubKey);
	free(encrypted_app_dek);

	if (ret != WAE_ERROR_NONE)
		free(dek);

	return ret;
}

int _get_app_dek_kek(unsigned char **pDekKek, size_t *kekLen)
{
	int ret = _read_from_file(_get_dek_kek_pri_key_path(), pDekKek, kekLen);

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("WAE: Fail to read APP_DEK_KEK Private Key");
		return ret;
	}

	/*
	    char* password = NULL;
	    ckmc_raw_buffer_s *pKekBuffer = NULL;
	    unsigned char* pKek = NULL;

	    char dek_kek_alias[MAX_ALIAS_LEN] = {0, };
	    _get_dek_kek_alias(dek_kek_alias, sizeof(dek_kek_alias));

	    ret = _to_wae_error(ckmc_get_data(dek_kek_alias, password, &pKekBuffer));
	    if(ret != WAE_ERROR_NONE) {
	        WAE_SLOGE("Fail to get APP_DEK_KEK from key-manager. alias=%s, ret=%d", APP_DEK_KEK_ALIAS, ret);
	        goto error;
	    }

	    pKek = (unsigned char*) malloc(pKekBuffer->size);
	    if(pKek == NULL) {
	        WAE_SLOGE("Fail to allocate a memory");
	        ret = WAE_ERROR_MEMORY;
	        goto error;
	    }
	    memcpy(pKek, pKekBuffer->data, pKekBuffer->size);

	    *pDekKek = pKek;
	    *kekLen = pKekBuffer->size;
	    WAE_SLOGI("Success to get APP_DEK_KEK from key-manager.");
	error:
	    if(pKekBuffer != NULL)
	        ckmc_buffer_free(pKekBuffer);
	    if(ret != WAE_ERROR_NONE && pKek != NULL)
	        free(pKek);
	*/
	return ret;
}

int _get_app_deks_loaded()
{
	char loading_done_alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_loading_done_alias(loading_done_alias, sizeof(loading_done_alias));

	ckmc_raw_buffer_s *pBuffer = NULL;
	int ret = _to_wae_error(ckmc_get_data(loading_done_alias, NULL, &pBuffer));

	if (ret == WAE_ERROR_NO_KEY)
		WAE_SLOGI("WAE: APP_DEK_LOADING was not done");
	else if (ret == WAE_ERROR_NONE)
		WAE_SLOGI("WAE: APP_DEK_LOADING was already done");
	else
		WAE_SLOGE("WAE: Fail to get information from key-manager about APP_DEK_LOADING_DONE_ALIAS. ret=%d", ret);

	ckmc_buffer_free(pBuffer);

	return ret;
}

int _set_app_deks_loaded()
{
	ckmc_raw_buffer_s buff;
	ckmc_policy_s policy;
	unsigned char dummyData[1] = {0};

	buff.data = dummyData;
	buff.size = sizeof(dummyData);

	policy.password = NULL;
	policy.extractable = true;

	char loading_done_alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_loading_done_alias(loading_done_alias, sizeof(loading_done_alias));

	int ret = _to_wae_error(ckmc_save_data(loading_done_alias, buff, policy));

	if (ret == WAE_ERROR_KEY_EXISTS) {
		WAE_SLOGI("WAE: APP_DEK_LOADING was already done");
		ret = WAE_ERROR_NONE;
	} else if (ret == WAE_ERROR_NONE) {
		WAE_SLOGI("Success to set APP_DEK_LOADING_DONE_ALIAS to key-manager.");
	} else {
		WAE_SLOGE("WAE: Fail to set APP_DEK_LOADING_DONE_ALIAS to key-manager. ret=%d", ret);
	}

	return ret;
}

int _clear_app_deks_loaded()
{
	char loading_done_alias[MAX_ALIAS_LEN] = {0, };
	_get_dek_loading_done_alias(loading_done_alias, sizeof(loading_done_alias));

	int ret = _to_wae_error(ckmc_remove_alias(loading_done_alias));

	if (ret == WAE_ERROR_NO_KEY) {
		WAE_SLOGI("APP_DEK_LOADING_DONE_ALIAS was not set to key-manager before.");
		ret = WAE_ERROR_NONE;
	} else if (ret == WAE_ERROR_NONE) {
		WAE_SLOGI("Success to clear app deks loaded");
	} else {
		WAE_SLOGE("Fail to clear APP_DEK_LOADING_DONE_ALIAS to key-manager. ret=%d", ret);
	}

	return ret;
}

int load_preloaded_app_deks(bool reload)
{
	int ret = WAE_ERROR_NONE;

	char pkgId[MAX_PKGID_LEN] = {0, };

	char file_path_buff[MAX_PATH_LEN];
	unsigned char *encrypted_app_dek = NULL;
	size_t encrypted_app_dek_len = 0;
	unsigned char *app_dek = NULL;
	size_t app_dek_len = 0;
	unsigned char *priKey = NULL;
	size_t priKeyLen = 0;

	int error_during_loading = 0;

	if (!reload) {
		// check if all deks were already loaded into key-manager.
		ret = _get_app_deks_loaded();

		if (ret == WAE_ERROR_NONE)
			return ret;
	}

	ret = _get_app_dek_kek(&priKey, &priKeyLen);

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

		memset(file_path_buff, 0, sizeof(file_path_buff));
		ret = snprintf(file_path_buff, sizeof(file_path_buff), "%s/%s",
					   _get_dek_store_path(), entry.d_name);

		if (ret < 0) {
			WAE_SLOGE("Failed to make file path by snprintf.");
			ret = WAE_ERROR_INVALID_PARAMETER; /* buffer size too small */
			goto error;
		}

		ret = _extract_pkg_id_from_file_name(entry.d_name, pkgId);

		if (ret != WAE_ERROR_NONE) {
			WAE_SLOGW("Fail to extract pkgid from file. It will be ignored. file=%s", file_path_buff);
			continue;
		}

		ret = _read_from_file(file_path_buff, &encrypted_app_dek, &encrypted_app_dek_len);

		if (ret != WAE_ERROR_NONE || encrypted_app_dek == NULL) {
			error_during_loading++;
			WAE_SLOGW("Fail to read file. It will be ignored. file=%s", file_path_buff);
			continue;
		}

		ret = decrypt_app_dek(priKey, priKeyLen, APP_DEK_KEK_PRIKEY_PASSWORD,
							  encrypted_app_dek, encrypted_app_dek_len,
							  &app_dek, &app_dek_len);

		if (ret != WAE_ERROR_NONE || app_dek == NULL) {
			error_during_loading++;
			WAE_SLOGW("Fail to decrypt APP DEK. It will be ignored. file=%s", file_path_buff);
			continue;
		}

		// save app_dek in key_manager
		ret = _add_dek_to_key_manager(pkgId, WAE_PRELOADED_APP, app_dek, app_dek_len);
		// free temp objects
		free(app_dek);
		free(encrypted_app_dek);
		app_dek = NULL;
		encrypted_app_dek = NULL;

		if (ret == WAE_ERROR_KEY_EXISTS) {
			WAE_SLOGI("Key Manager already has APP_DEK. It will be ignored. file=%s", file_path_buff);
		} else if (ret != WAE_ERROR_NONE) {
			error_during_loading++;
			WAE_SLOGW("Fail to add APP DEK to key-manager. file=%s", file_path_buff);
		}
	}

	ret = _set_app_deks_loaded();

	if (ret == WAE_ERROR_NONE) {
		WAE_SLOGI("Success to load_preloaded_app_deks");
		ret = WAE_ERROR_NONE;
	} else {
		WAE_SLOGW("Fail to _set_app_deks_loaded to key-manager. ret=%d", ret);
	}

error:
	free(priKey);

	if (dir)
		closedir(dir);

	return ret;
}

int remove_app_dek(const char *pkgId, wae_app_type_e appType)
{
	char alias[MAX_ALIAS_LEN] = {0,};

	_get_alias(pkgId, appType, true, alias, sizeof(alias));

	int ret = _to_wae_error(ckmc_remove_alias(alias));

	if (ret != WAE_ERROR_NONE) {
		WAE_SLOGE("Fail to remove APP_DEK from  key-manager. pkgId=%s, alias=%s, ret=%d", pkgId, alias, ret);
		return ret;
	}

	_remove_app_dek_from_cache(pkgId);
	WAE_SLOGI("Success to remove APP_DEK from  key-manager. pkgId=%s", pkgId);

	return WAE_ERROR_NONE;
}
