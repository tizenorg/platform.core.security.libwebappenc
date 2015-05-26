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
 * @file        key-handler.c
 * @author      Dongsun Lee (ds73.lee@samsung.com) 
 * @version     1.0
 * @brief       a header for key manupulatation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ckmc/ckmc-manager.h>
#include "wae_log.h"
#include "web_app_enc.h"
#include "key_handler.h"
#include "crypto_service.h"

#define APP_DEK_KEK_PRIKEY_PASSWORD "wae_appdek_kek_1q2w3e4r"


typedef struct _dek_cache_element{
    char          pkgId[MAX_PKGID_LEN];
    unsigned char dek[DEK_LEN];
} dek_cache_element;

dek_cache_element APP_DEK_CACHE[MAX_CACHE_SIZE];
int NEXT_CACHE_IDX = -1;

void _initialize_cache()
{
    NEXT_CACHE_IDX = 0;
    memset(APP_DEK_CACHE, 0, sizeof(dek_cache_element)*MAX_CACHE_SIZE);    
}

unsigned char* _get_app_dek_from_cache(const char* pkgId)
{
    int i = 0;

    if(NEXT_CACHE_IDX < 0)
        _initialize_cache();

    for(i =0; i<MAX_CACHE_SIZE; i++) {
        //WAE_SLOGI("CACHED APP_DEK[%d]=%s", i, APP_DEK_CACHE[i].pkgId);
        if( strlen(APP_DEK_CACHE[i].pkgId) == strlen(pkgId) &&
            strncmp(pkgId, APP_DEK_CACHE[i].pkgId, strlen(pkgId)) == 0) {
            return APP_DEK_CACHE[i].dek;
        }
    }
    return NULL;
}

void _add_app_dek_to_cache(const char* pkgId, unsigned char* dek)
{
    int i = 0;

    if(NEXT_CACHE_IDX < 0)
        _initialize_cache();

    // if existing one has the same pkgid
    for(i =0; i<MAX_CACHE_SIZE; i++) {
        if( strlen(APP_DEK_CACHE[i].pkgId) == strlen(pkgId) &&
            strncmp(pkgId, APP_DEK_CACHE[i].pkgId, strlen(pkgId)) == 0) {
            memcpy(APP_DEK_CACHE[i].dek, dek, DEK_LEN);
            return;
        }
    }

    // for new pkgid
    strncpy(APP_DEK_CACHE[NEXT_CACHE_IDX].pkgId, pkgId, strlen(pkgId));
    memcpy(APP_DEK_CACHE[NEXT_CACHE_IDX].dek, dek, DEK_LEN);

    NEXT_CACHE_IDX++;
    if(NEXT_CACHE_IDX >= MAX_CACHE_SIZE)
        NEXT_CACHE_IDX = 0;
}

void _remove_app_dek_from_cache(const char* pkgId) 
{
    int i = 0;

    for(i =0; i<MAX_CACHE_SIZE; i++) {
        if( strlen(APP_DEK_CACHE[i].pkgId) == strlen(pkgId) &&
            strncmp(pkgId, APP_DEK_CACHE[i].pkgId, strlen(pkgId)) == 0) {
            memset(APP_DEK_CACHE[i].pkgId, 0, sizeof(APP_DEK_CACHE[i].pkgId));
            return;
        }
    }

}

int _to_wae_error(int key_manager_error)
{
	switch(key_manager_error) {
        case CKMC_ERROR_NONE:                return WAE_ERROR_NONE;
        case CKMC_ERROR_INVALID_PARAMETER:   return WAE_ERROR_INVALID_PARAMETER;
        case CKMC_ERROR_PERMISSION_DENIED:   return WAE_ERROR_PERMISSION_DENIED;
        case CKMC_ERROR_DB_ALIAS_UNKNOWN:    return WAE_ERROR_NO_KEY;
        case CKMC_ERROR_DB_ALIAS_EXISTS:     return WAE_ERROR_KEY_EXISTS;
        default:                             return WAE_ERROR_KEY_MANAGER;
    }
}

int _get_random(int length, unsigned char* random)
{
    FILE* f = NULL;
    int i = 0;
    int ch = 0;
    //read random file 
    if((f = fopen(RANDOM_FILE, "r")) != NULL){
        while( i < length){
            if((ch = fgetc(f)) == EOF){
                break;
            }
            random[i] = (unsigned char) ch;
            i++;
        }
    }
    if(f != NULL)
        fclose(f);
    return WAE_ERROR_NONE;
}

void _get_alias(const char* pPkgId, char* alias) 
{
   sprintf(alias, "%s%s", APP_DEK_ALIAS_PFX, pPkgId); 
}

int _add_dek_to_key_manager(const char* pPkgId, const unsigned char* pDek, const int len)
{
    int ret = WAE_ERROR_NONE;
    char alias[MAX_ALIAS_LEN] = {0,};
    ckmc_raw_buffer_s buff;
    ckmc_policy_s policy;

    buff.data = (unsigned char *)pDek;
    buff.size = len;

    policy.password = NULL;
    policy.extractable = true;

    // save app_dek in key_manager
    _get_alias(pPkgId, alias);

    // even if it fails to remove, ignore it.
    ret = _to_wae_error( ckmc_remove_alias(alias));

    ret = _to_wae_error(ckmc_save_data(alias, buff, policy));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to add APP_DEK to key-manager. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }

    // share app_dek for web app laucher to use app_dek
    ret = _to_wae_error(ckmc_set_permission(alias, pPkgId, CKMC_PERMISSION_READ));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to set_permission to APP_DEK. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }
    WAE_SLOGI("Success to add APP_DEK to key-manager. pkgId=%s", pPkgId);
error:
    return ret;
}


int _get_preloaded_app_dek_file_path(const char* pPkgId, char *path)
{
    sprintf(path, "%s/%s_%s.adek", APP_DEK_STORE_DIR, APP_DEK_FILE_PFX, pPkgId);
    return WAE_ERROR_NONE;
}

int _extract_pkg_id_from_file_name(const char* fileName, char* pkgId)
{
    char* start = strstr(fileName, APP_DEK_FILE_PFX);
    if(start == NULL){
        WAE_SLOGE("Fail to extract pkgid from APP_DEK file. fileName=%s", fileName);
        return WAE_ERROR_FILE;
    }
    start = start + strlen(APP_DEK_FILE_PFX) + 1;
    char* end = strstr(fileName, ".adek");
    if(start == NULL){
        WAE_SLOGE("Fail to extract pkgid from APP_DEK file. fileName=%s", fileName);
        return WAE_ERROR_FILE;
    }
    strncpy(pkgId, start, end-start);
    pkgId[end-start] = 0;//terminate string
    return WAE_ERROR_NONE;
}

int _read_encrypted_app_dek_from_file(const char* pPkgId, unsigned char** encrypted_app_dek, int *len)
{
    char path[MAX_PATH_LEN] = {0,};
    _get_preloaded_app_dek_file_path(pPkgId, path);
    return _read_from_file(path, encrypted_app_dek, len);
}

int _write_encrypted_app_dek_to_file(const char* pPkgId, const unsigned char* encrypted_app_dek, int len)
{
    char path[MAX_PATH_LEN] = {0,};
    _get_preloaded_app_dek_file_path(pPkgId, path);
    return _write_to_file( path, encrypted_app_dek, len);
}

int _read_from_file(const char* path, unsigned char** data, int* len) 
{
    int ret = WAE_ERROR_NONE;
    FILE* f = NULL;
    int file_len = -1;
    unsigned char* file_contents = NULL;
    int ch = 0;
    int i = 0;

    f = fopen(path, "r");
    if( f == NULL) {
        WAE_SLOGE("Fail to open a file. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    fseek(f, 0, SEEK_END); // move to the end of a file
    file_len = ftell(f);
    fseek(f, 0, SEEK_SET); // move to the start of a file

    file_contents = (unsigned char*) malloc(file_len);
    if(file_contents == NULL) {
         WAE_SLOGE("Fail to allocate memory for encrypted_app_dek");
         ret = WAE_ERROR_MEMORY;
         goto error;
    }
    memset(file_contents, 0x00, file_len);

    while( (ch = fgetc(f)) != EOF) {
        file_contents[i++]=(char)ch;
    } 

    *data = file_contents;
    *len = file_len;
    
error:
    if(f != NULL)
        fclose(f);
    if(ret != WAE_ERROR_NONE && file_contents != NULL)
        free(file_contents);

    return ret;
}

int _write_to_file(const char* path, const unsigned char* data, const int len)
{
    int ret = WAE_ERROR_NONE;

    FILE* f = NULL;
    int write_len = -1;

    f = fopen(path, "w");
    if( f == NULL) {
        WAE_SLOGE("Fail to open a file. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    write_len = fwrite(data, 1, len, f);
    if(write_len != len) {
        WAE_SLOGE("Fail to write a file. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }
error:
    if(f != NULL)
        fclose(f);

    return ret;
}

int get_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen)
{
    int ret = WAE_ERROR_NONE;

    char* password = NULL;
    ckmc_raw_buffer_s *pDekBuffer = NULL;
    char alias[MAX_ALIAS_LEN] = {0,};
    unsigned char* pDek = NULL;
    unsigned char* cached_dek = NULL;

    // get dek from cache
    cached_dek = _get_app_dek_from_cache(pPkgId);
    if(cached_dek == NULL) {
        // get APP_DEK from system database
        _get_alias(pPkgId, alias);

        ret = _to_wae_error(ckmc_get_data(alias, password, &pDekBuffer));
        if(ret != WAE_ERROR_NONE) {
            WAE_SLOGE("Fail to get APP_DEK from key-manager. alias=%s, ret=%d", alias, ret);
            goto error;
        }
    }

    pDek = (unsigned char*) malloc(DEK_LEN);
    if(pDek == NULL) {
        WAE_SLOGE("Fail to allocate a memory");
        ret = WAE_ERROR_MEMORY;
        goto error;
    }
    memcpy(pDek, (cached_dek != NULL) ? cached_dek : pDekBuffer->data, DEK_LEN);

    *ppDek = pDek;
    *dekLen = DEK_LEN;
    WAE_SLOGI("Success to get APP_DEK from key-manager. pkgId=%s", pPkgId);
error:
    if(pDekBuffer != NULL)
        ckmc_buffer_free(pDekBuffer);
    if(ret != WAE_ERROR_NONE && pDek != NULL)
        free(pDek);

    return ret;
}

int create_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen)
{
    int ret = WAE_ERROR_NONE;
    unsigned char *dek= NULL;

    dek = (unsigned char*) malloc(DEK_LEN);
    if(dek  == NULL) {
        ret = WAE_ERROR_MEMORY;
        goto error;
    }

    ret = _get_random(DEK_LEN, dek);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to get random for APP_DEK. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }

    // save app_dek in key_manager
    ret = _add_dek_to_key_manager(pPkgId, dek, DEK_LEN);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

    // store APP_DEK in cache
    _add_app_dek_to_cache(pPkgId, dek);

    *ppDek = dek;
    *dekLen = DEK_LEN;
    
    WAE_SLOGI("Success to create APP_DEK and store it in key-manager. pkgId=%s", pPkgId);
error:
    if(ret != WAE_ERROR_NONE && dek != NULL)
        free(dek);

    return ret;
}

int get_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen)
{
    int ret = WAE_ERROR_NONE;
    unsigned char* cached_dek= NULL;
    unsigned char* dek = NULL;

    // get dek from cache
    cached_dek = _get_app_dek_from_cache(pPkgId);
    if(cached_dek == NULL) {
        WAE_SLOGE("Fail to get APP_DEK from cache for preloaded app");
        ret = WAE_ERROR_NO_KEY;
        goto error;
    }

    dek = (unsigned char*) malloc(DEK_LEN);
    if(dek == NULL) {
        WAE_SLOGE("Fail to allocate memory for preloaded app dek");
        ret = WAE_ERROR_MEMORY;
        goto error;
    }
    memcpy(dek, cached_dek, DEK_LEN);

    *ppDek = dek;
    *dekLen = DEK_LEN;
error:
    if(ret != WAE_ERROR_NONE && dek != NULL)
        free(dek);
    
    return ret;
}

int create_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen)
{
    int ret = WAE_ERROR_NONE;
    unsigned char* dek = NULL;
    unsigned char*encrypted_app_dek = NULL;
    int encrypted_app_dek_len = 0;
    unsigned char* pubKey = NULL;
    int pubKeyLen = 0;

    // create APP_DEK
    dek = (unsigned char*) malloc(DEK_LEN);
    if(dek == NULL) {
        ret = WAE_ERROR_MEMORY;
        goto error;
    }

    ret = _get_random(DEK_LEN, dek);
    if(ret != WAE_ERROR_NONE) {
        return ret;
    }

    // encrypt APP_DEK with APP_DEK_KEK
    ret = _read_from_file(APP_DEK_KEK_PUB_KEY_PATH, &pubKey, &pubKeyLen);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to read APP_DEK_KEK Public Key");
        return ret;
    }

    ret = encrypt_app_dek(pubKey, pubKeyLen, dek, DEK_LEN, &encrypted_app_dek, &encrypted_app_dek_len);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to encrypt APP_DEK with APP_DEK_KEK");
        return ret;
    }

    // write APP_DEK in a file
    ret = _write_encrypted_app_dek_to_file(pPkgId, encrypted_app_dek, encrypted_app_dek_len);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to write encrypted APP_DEK. pkgId=%s", pPkgId);
        return ret;
    }

    // store APP_DEK in cache
    _add_app_dek_to_cache(pPkgId, dek);

    *ppDek = dek;
    *dekLen = DEK_LEN;
    WAE_SLOGI("Success to create preleaded APP_DEK and write it in initail value file. pkgId=%s", pPkgId);

error:
    if(pubKey != NULL)
        free(pubKey);
    if(encrypted_app_dek != NULL)
        free(encrypted_app_dek);
    if(ret != WAE_ERROR_NONE && dek != NULL)
        free(dek);
    return ret;
}


int _get_app_dek_kek(unsigned char** ppDekKek, int* kekLen)
{
    int ret = WAE_ERROR_NONE;

    ret = _read_from_file(APP_DEK_KEK_PRI_KEY_PATH, ppDekKek, kekLen);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to read APP_DEK_KEK Private Key");
        return ret;
    }
/*
    char* password = NULL;
    ckmc_raw_buffer_s *pKekBuffer = NULL;
    unsigned char* pKek = NULL;


    ret = _to_wae_error(ckmc_get_data(APP_DEK_KEK_ALIAS, password, &pKekBuffer));
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

    *ppDekKek = pKek;
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
    int ret = WAE_ERROR_NONE;

    ckmc_raw_buffer_s *pBuffer = NULL;

    ret = _to_wae_error(ckmc_get_data(APP_DEK_LOADING_DONE_ALIAS, NULL, &pBuffer));
    if(ret == WAE_ERROR_NO_KEY) {
        WAE_SLOGI("APP_DEK_LOADING was not done");
    } else if(ret == WAE_ERROR_NONE) {
        WAE_SLOGI("APP_DEK_LOADING was already done");
    } else {
        WAE_SLOGE("Fail to get information from key-manager about APP_DEK_LOADING_DONE_ALIAS. ret=%d", ret);
        goto error;
    }

error:
    if(pBuffer != NULL)
        ckmc_buffer_free(pBuffer);

    return ret;
}

int _set_app_deks_loaded()
{
    int ret = WAE_ERROR_NONE;
    ckmc_raw_buffer_s buff;
    ckmc_policy_s policy;
    unsigned char dummyData[1] =  {0, };

    buff.data = dummyData;
    buff.size = sizeof(dummyData);

    policy.password = NULL;
    policy.extractable = true;

    ret = _to_wae_error(ckmc_save_data(APP_DEK_LOADING_DONE_ALIAS, buff, policy));
    if(ret == WAE_ERROR_KEY_EXISTS) {
        WAE_SLOGI("APP_DEK_LOADING was already done");
    } else if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to set APP_DEK_LOADING_DONE_ALIAS to key-manager. ret=%d", ret);
        goto error;
    }

    WAE_SLOGI("Success to set APP_DEK_LOADING_DONE_ALIAS to key-manager.");
error:
    return ret;
}

int _clear_app_deks_loaded()
{
    int ret = WAE_ERROR_NONE;

    ret = _to_wae_error(ckmc_remove_alias(APP_DEK_LOADING_DONE_ALIAS));
    if(ret == WAE_ERROR_NO_KEY) {
        WAE_SLOGI("APP_DEK_LOADING_DONE_ALIAS was not set to key-manager before.");
        ret = WAE_ERROR_NONE;
    }else if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to clear APP_DEK_LOADING_DONE_ALIAS to key-manager. ret=%d", ret);
    }

    return ret;
}

int load_preloaded_app_deks(int reload)
{
    int ret = WAE_ERROR_NONE;

    char pkgId[MAX_PKGID_LEN] = {0, };

    DIR *dir = NULL;
    struct dirent entry;
    struct dirent *result;
    int error;
    char file_path_buff[MAX_PATH_LEN];
    unsigned char* encrypted_app_dek = NULL;
    int encrypted_app_dek_len = 0;
    unsigned char* app_dek = NULL;
    int app_dek_len = 0;
    unsigned char* priKey = NULL;
    int priKeyLen = 0;

    int error_during_loading = 0;

    if(reload != WAE_TRUE) {
        // check if all deks were already loaded into key-manager.
        ret = _get_app_deks_loaded(); 
        if(ret == WAE_ERROR_NONE) {
            return ret;
        }
    }

    ret = _get_app_dek_kek(&priKey, &priKeyLen);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to get APP_DEK_KEK Private Key");
        return ret;
    }

    dir = opendir(APP_DEK_STORE_DIR);
    if(dir == NULL) {
        WAE_SLOGE("Fail to open dir. dir=%s", APP_DEK_STORE_DIR);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    for(;;) {
        error = readdir_r(dir, &entry, &result);
        if( error != 0 ) {
            ret = WAE_ERROR_FILE;
            goto error;
        }
        // readdir_r returns NULL in *result if the end
        // of the directory stream is reached
        if(result == NULL)
            break;

        // regular file && start with KEY_MANAGER_INITIAL_VALUE_FILE_PFX
        if(entry.d_type == DT_REG && strstr(entry.d_name, APP_DEK_FILE_PFX) != NULL) { 
            memset(file_path_buff, 0, sizeof(file_path_buff));
            sprintf(file_path_buff, "%s/%s", APP_DEK_STORE_DIR, entry.d_name);

            ret = _extract_pkg_id_from_file_name(entry.d_name, pkgId);
            if(ret != WAE_ERROR_NONE) {
                WAE_SLOGW("Fail to extract pkgid from file. It will be ignored. file=%s",file_path_buff);
                continue;
            }

            ret = _read_from_file(file_path_buff, &encrypted_app_dek, &encrypted_app_dek_len);
            if(ret != WAE_ERROR_NONE || encrypted_app_dek == NULL) {
                error_during_loading++;
                WAE_SLOGW("Fail to read file. It will be ignored. file=%s",file_path_buff);
                continue;
            }

            ret = decrypt_app_dek(priKey, priKeyLen, APP_DEK_KEK_PRIKEY_PASSWORD,
                                  encrypted_app_dek, encrypted_app_dek_len, 
                                  &app_dek, &app_dek_len);
            if(ret != WAE_ERROR_NONE || app_dek == NULL) {
                error_during_loading++;
                WAE_SLOGW("Fail to decrypt APP DEK. It will be ignored. file=%s",file_path_buff);
                continue;
            }

            // save app_dek in key_manager
            ret = _add_dek_to_key_manager(pkgId, app_dek, app_dek_len);
            // free temp objects
            free(app_dek);
            free(encrypted_app_dek);
            app_dek = NULL;
            encrypted_app_dek = NULL;

            if(ret == WAE_ERROR_KEY_EXISTS) {
                WAE_SLOGI("Key Manager already has APP_DEK. It will be ignored. file=%s",file_path_buff);
                continue;
            }else if(ret != WAE_ERROR_NONE) {
                error_during_loading++;
                WAE_SLOGW("Fail to add APP DEK to key-manager. file=%s",file_path_buff);
                continue;
            }
        }
    }

    _set_app_deks_loaded();
    WAE_SLOGI("Success to load_preloaded_app_deks");
    ret = WAE_ERROR_NONE;
error:
    if(priKey != NULL)
        free(priKey);

    return ret;
}


int remove_app_dek(const char* pPkgId)
{
    int ret = CKMC_ERROR_NONE;
    char alias[MAX_ALIAS_LEN] = {0,};

    _get_alias(pPkgId, alias);

    ret = _to_wae_error(ckmc_remove_alias(alias));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to remove APP_DEK from  key-manager. pkgId=%s, alias=%s, ret=%d", pPkgId, alias, ret);
        goto error;
    }

    _remove_app_dek_from_cache(pPkgId);
    WAE_SLOGI("Success to remove APP_DEK from  key-manager. pkgId=%s", pPkgId);
error:
    return WAE_ERROR_NONE;
}
