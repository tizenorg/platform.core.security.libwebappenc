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



int _to_wae_error(int key_manager_error)
{
	switch(key_manager_error) {
        case CKMC_ERROR_NONE:                return WAE_ERROR_NONE;
        case CKMC_ERROR_INVALID_PARAMETER:   return WAE_ERROR_INVALID_PARAMETER;
        case CKMC_ERROR_PERMISSION_DENIED:   return WAE_ERROR_PERMISSION_DENIED;
        case CKMC_ERROR_DB_ALIAS_UNKNOWN:    return WAE_ERROR_NO_KEY;
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

void _get_system_alias(const char* pPkgId, char* alias) 
{
   //sprintf(alias, "/ %s%s", APP_DEK_ALIAS_PFX, pPkgId); 
   sprintf(alias, "%s%s", APP_DEK_ALIAS_PFX, pPkgId); 
}

int _add_dek_to_key_manager(const char* pPkgId, const unsigned char* pDek, const int len)
{

    int ret = WAE_ERROR_NONE;
    char alias[MAX_ALIAS_LEN] = {0,};
    char sys_alias[MAX_ALIAS_LEN] = {0,};
    ckmc_raw_buffer_s buff;
    ckmc_policy_s policy;

    buff.data = (unsigned char *)pDek;
    buff.size = len;

    policy.password = NULL;
    policy.extractable = true;

    // even if it fails to remove, ignore it.
    ret = _to_wae_error( ckmc_remove_alias(alias));

    // save app_dek in key_manager
    _get_alias(pPkgId, alias);
    ret = _to_wae_error(ckmc_save_data(alias, buff, policy));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to add APP_DEK to key-manager. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }

    // share app_dek for web app laucher to use app_dek
    _get_system_alias(pPkgId, sys_alias);
    ret = _to_wae_error(ckmc_set_permission(sys_alias, pPkgId, CKMC_PERMISSION_READ));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to set_permission to APP_DEK. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }
    WAE_SLOGI("Success to add APP_DEK to key-manager. pkgId=%s", pPkgId);
error:
    return ret;
}

int _get_initial_value_file_path(const char* pPkgId, char *path) 
{
    sprintf(path, "%s/%s_%s.xml", KEY_MANAGER_INITIAL_VALUE_DIR, KEY_MANAGER_INITIAL_VALUE_FILE_PFX, pPkgId);
    return WAE_ERROR_NONE;
}

int _write_initial_value_file(const char* pPkgId, const unsigned char* dek)
{
    int ret = WAE_ERROR_NONE;

    char hex_dek[DEK_LEN*2+1] = {0, };
    char initial_value[1024] = {0, };
    char alias[MAX_ALIAS_LEN] = {0,};
    char path[MAX_PATH_LEN] = {0,};
    FILE* f = NULL;
    int i = 0;

    const char* INITIAL_VALUE_FILE_TEMPLATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                         "<InitialValues version=\"0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
                                                     " xsi:noNamespaceSchemaLocation=\"initial_values.xsd\">\n"
                         "    <Data name=\"%s\">\n"
                         "        <ASCII>%s</ASCII>\n"
                         "        <Permission accessor=\"%s\"/>\n"
                         "    </Data>\n"
                         "</InitialValues>\n";


    _get_alias(pPkgId, alias);

    for(i=0; i<DEK_LEN; i++) {
        sprintf(hex_dek + (i*2),"%02x", dek[i]);
    }

    sprintf(initial_value, INITIAL_VALUE_FILE_TEMPLATE, alias, hex_dek, pPkgId);

    _get_initial_value_file_path(pPkgId, path);
    f = fopen(path, "w");
    if( f == NULL) {
        WAE_SLOGE("Fail to open a file. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    if(fprintf(f, "%s", initial_value) <= 0) {
        WAE_SLOGE("Fail to write a file. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    WAE_SLOGI("Success to write a initial value file. file=%s", path);
error:
    if(f != NULL)
        fclose(f);
    return ret;
}

int _read_initial_value_file(const char* path, char* pkgId, unsigned char* dek)
{
    int ret = WAE_ERROR_NONE;

    FILE* f = NULL;
    char file_buff[1024*2] = {0, };
    char hex_dek[DEK_LEN*2+1] = {0, };

    const char* dekPfx = "<ASCII>";
    const char* dekSfx = "</ASCII>";
    const char* pkgidPfx = "accessor=\"";
    const char* pkgidSfx = "\"/>";

    char *idxStart = NULL;
    char *idxEnd = NULL;
    char ch = 0;
    int i = 0;
    
    f = fopen(path, "r");
    if( f == NULL) {
        WAE_SLOGE("Fail to open a file. file=%s", path);
        ret = WAE_ERROR_NO_KEY;
        goto error;
    }

    while( (ch = fgetc(f)) != EOF ) {
        file_buff[i++]=ch;
    }

    idxStart = strstr(file_buff, dekPfx) + strlen(dekPfx);
    idxEnd   = strstr(idxStart, dekSfx);
    if(idxStart == NULL || idxEnd == NULL || idxStart > idxEnd) {
        WAE_SLOGE("Fail to read dek. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }
    if((idxEnd - idxStart) != DEK_LEN * 2) {
        WAE_SLOGE("Invalid dek size in file. file=%s, size=%d", path, (idxEnd - idxStart));
        ret = WAE_ERROR_FILE;
        goto error;
    }
    strncpy(hex_dek, idxStart, (idxEnd-idxStart));

    for(i=0; i<DEK_LEN; i++) {
        sscanf(hex_dek + (i*2), "%02x", (unsigned int *)(&(dek[i])));
    }

    idxStart = strstr(file_buff, pkgidPfx) + strlen(pkgidPfx);
    idxEnd   = strstr(idxStart, pkgidSfx);
    if(idxStart == NULL || idxEnd == NULL || idxStart > idxEnd) {
        WAE_SLOGE("Fail to read pkgid. file=%s", path);
        ret = WAE_ERROR_FILE;
        goto error;
    }
    strncpy(pkgId, idxStart, (idxEnd-idxStart));

    WAE_SLOGI("Success to read a initial value file. file=%s", path);
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

    // TODO: Caching

    // get APP_DEK from system database
    _get_system_alias(pPkgId, alias);

    ret = _to_wae_error(ckmc_get_data(alias, password, &pDekBuffer));
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to get APP_DEK from key-manager. alias=%s, ret=%d", alias, ret);
        goto error;
    }

    pDek = (unsigned char*) malloc(pDekBuffer->size);
    if(pDek == NULL) {
        WAE_SLOGE("Fail to allocate a memory");
        ret = WAE_ERROR_MEMORY;
        goto error;
    }
    memcpy(pDek, pDekBuffer->data, pDekBuffer->size);

    *ppDek = pDek;
    *dekLen = pDekBuffer->size;
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
    unsigned char *random = NULL;

    random = (unsigned char*) malloc(DEK_LEN);
    if(random == NULL) {
        ret = WAE_ERROR_MEMORY;
        goto error;
    }

    ret = _get_random(DEK_LEN, random);
    if(ret != WAE_ERROR_NONE) {
        WAE_SLOGE("Fail to get random for APP_DEK. pkgId=%s, ret=%d", pPkgId, ret);
        goto error;
    }

    // save app_dek in key_manager
    ret = _add_dek_to_key_manager(pPkgId, random, DEK_LEN);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

    *ppDek = random;
    *dekLen = DEK_LEN;

    // TODO: Caching
    WAE_SLOGI("Success to create APP_DEK and store it in key-manager. pkgId=%s", pPkgId);
error:
    if(ret != WAE_ERROR_NONE && random != NULL)
        free(random);

    return ret;
}

int get_preloaded_app_dek(const char* pPkgId, unsigned char** ppDek, int* dekLen)
{
    int ret = WAE_ERROR_NONE;
    char path[MAX_PATH_LEN] = {0,};
    char readPkgId[MAX_PKGID_LEN] = {0 };
    unsigned char* dek = NULL;

    // TODO: Caching

    dek = (unsigned char*) malloc(DEK_LEN);
    if(dek == NULL) {
        WAE_SLOGE("Fail to allocate memory for preloaded app dek");
        ret = WAE_ERROR_MEMORY;
        goto error;
    }

    _get_initial_value_file_path(pPkgId, path);

    ret = _read_initial_value_file(path, readPkgId, dek);
    if(ret != WAE_ERROR_NONE) {
        goto error;
    }

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

    dek = (unsigned char*) malloc(DEK_LEN);
    if(dek == NULL) {
        ret = WAE_ERROR_MEMORY;
        goto error;
    }

    ret = _get_random(DEK_LEN, dek);
    if(ret != WAE_ERROR_NONE) {
        return ret;
    }

    ret = _write_initial_value_file(pPkgId, dek);
    if(ret != WAE_ERROR_NONE) {
        return ret;
    }

    *ppDek = dek;
    *dekLen = DEK_LEN;
    WAE_SLOGI("Success to create preleaded APP_DEK and write it in initail value file of key-manager. pkgId=%s", pPkgId);
error:
    if(ret != WAE_ERROR_NONE && dek != NULL)
        free(dek);
    return ret;
}

int load_preloaded_app_deks()
{
    int ret = WAE_ERROR_NONE;

    char pkgId[MAX_PKGID_LEN] = {0, };
    unsigned char dek[DEK_LEN] = {0, };

    DIR *dir = NULL;
    struct dirent entry;
    struct dirent *result;
    int error;
    char file_path_buff[MAX_PATH_LEN];

    dir = opendir(KEY_MANAGER_INITIAL_VALUE_DIR);
    if(dir == NULL) {
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
        if(entry.d_type == DT_REG && strstr(entry.d_name, KEY_MANAGER_INITIAL_VALUE_FILE_PFX) != NULL) { 
            memset(file_path_buff, 0, sizeof(file_path_buff));
            sprintf(file_path_buff, "%s/%s", KEY_MANAGER_INITIAL_VALUE_DIR, entry.d_name);

            ret = _read_initial_value_file(file_path_buff, pkgId, dek);

            // save app_dek in key_manager
            ret = _add_dek_to_key_manager(pkgId, dek, DEK_LEN);
            if(ret != WAE_ERROR_NONE) {
                goto error;
            }
            
            // remove file
            unlink(file_path_buff);
            WAE_SLOGI("Success to load_preloaded_app_dek. file=%s",file_path_buff);
        }
    }
    WAE_SLOGI("Success to load_preloaded_app_deks");
error:
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

    WAE_SLOGI("Success to remove APP_DEK from  key-manager. pkgId=%s", pPkgId);
error:
    return WAE_ERROR_NONE;
}
