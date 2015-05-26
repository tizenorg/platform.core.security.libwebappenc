#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "web_app_enc.h"
#include "key_handler.h"
#include "crypto_service.h"

static int tc_seq = 1;
static int RUNTC(int (*tc_method)(), const char* tc_name)
{
    int ret = WAE_ERROR_NONE;
    printf("[%02d:%s]started...\n", tc_seq, tc_name);
    ret = tc_method();
    if(ret == WAE_ERROR_NONE)
        printf("[%02d:%s]ended. SUCCESS\n\n", tc_seq, tc_name);
    else
        printf("[%02d:%s]ended. FAIL. error=%d\n\n", tc_seq, tc_name, ret);
    tc_seq++;
    return ret;
}


void _print_binary_to_hex(const char* msg, unsigned char* bin, int len)
{
    int i = 0;
    printf("%s", msg);
    for(i=0; i<len; i++) {
        printf("%02x", bin[i]);
    }
    printf("\n");
}

int _compare_binary(const unsigned char* b1, int b1Len, const unsigned char* b2, int b2Len)
{
    int i = 0;
    if(b1Len != b2Len)
        return b1Len - b2Len;
    for(i=0; i<b1Len; i++) {
        if(b1[i] != b2[i])
            return b1[i] - b2[i];
    } 
    return 0;
}

int wae_tc_get_random()
{
    int ret = WAE_ERROR_NONE;

    int rand_len = 32;
    unsigned char random[32] = {0, };

    ret = _get_random(rand_len, random);

    _print_binary_to_hex("...RANDOM = ", random, sizeof(random));
    
    return ret;
}

int wae_tc_encrypt_decrypt_aes_cbc()
{
    int ret = WAE_ERROR_NONE;

    unsigned char dek[32] = {0, };
    int keyLen = 32;
    const char* plaintext= "adbdfdfdfdfdererfdfdfererfdrerfdrer";
    int plaintextLen = strlen(plaintext);
    unsigned char* encrypted = NULL;
    int encLen = 0;
    unsigned char* decrypted = NULL;
    int decLen = 0;
    char decrypted_str[1024] = {0, };

    ret = _get_random(keyLen, dek);

    ret = encrypt_aes_cbc(dek, keyLen, (const unsigned char*)plaintext, plaintextLen, &encrypted, &encLen);
    if(ret != WAE_ERROR_NONE){
        printf("...FAIL: encrypt_aes_cbc. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = decrypt_aes_cbc(dek, keyLen, encrypted, encLen, &decrypted, &decLen);
    if(ret != WAE_ERROR_NONE){
        printf("...FAIL: decrypt_aes_cbc. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    if(plaintextLen != decLen) {
        printf("...FAIL: plaintextLen(%d) != decLen(%d)\n", plaintextLen, decLen);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    memcpy(decrypted_str, decrypted, decLen);
    printf("...plaintext = %s\n", plaintext);
    printf("...decrypted = %s\n", decrypted_str);
    if(strcmp(plaintext, decrypted_str) != 0) {
        printf("...FAIL: plaintext(%s) != decrypted(%s)\n", plaintext, decrypted_str);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

error:
    if(encrypted != NULL)
        free(encrypted);
    if(decrypted != NULL)
        free(decrypted);

    return ret;
}

int wae_tc_get_alias()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    char alias[256] = {0, };
    char sys_alias[256] = {0, };

    _get_alias(pkgId, alias);
    _get_system_alias(pkgId, sys_alias);

    printf("...pkgid=%s, alias=%s, system alias=%s\n", pkgId, alias, sys_alias);

    return ret;
}

int wae_tc_add_get_remove_dek()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    char alias[256] = {0, };
    char sys_alias[256] = {0, };

    int dekLen= 32;
    unsigned char dek[32] = {0, };
    int storedDekLen = 0;
    unsigned char* storedDek = NULL;

    ret = _get_random(dekLen, dek);

    _get_alias(pkgId, alias);
    _get_system_alias(pkgId, sys_alias);

    remove_app_dek(pkgId);

    ret = _add_dek_to_key_manager(pkgId, dek, dekLen);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: _add_dek_to_key_manager. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    if(_compare_binary(dek, dekLen, storedDek, storedDekLen) != 0 ) {
        ret = WAE_ERROR_KEY_MANAGER;
        printf("...FAIL: DEK != STORED_DEK.\n");
        goto error;
    }

    ret = remove_app_dek(pkgId);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: remove_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret == WAE_ERROR_NONE) {
        ret = WAE_ERROR_UNKNOWN;
        printf("...FAIL: APP DEK still exists in key_manager.\n");
        goto error;
    }
    
    ret = WAE_ERROR_NONE;
error:
    if(storedDek != NULL)
        free(storedDek);

    return ret;
}

int wae_tc_initail_value()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    int dekLen= 32;
    unsigned char dek[32] = {0, };
    char readPkgId[MAX_PKGID_LEN] = {0, };
    unsigned char readDek[32] = {0, };
    char path[MAX_PATH_LEN] = {0, };

    sprintf(path, "%s/%s_%s.xml", KEY_MANAGER_INITIAL_VALUE_DIR, KEY_MANAGER_INITIAL_VALUE_FILE_PFX, pkgId);
    unlink(path);

    _get_random(dekLen, dek);

    ret = _write_initial_value_file(pkgId, dek);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: _write_initial_value_file.\n");
        goto error;
    }

    ret = _read_initial_value_file(path, readPkgId, readDek);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: _read_initial_value_file.\n");
        goto error;
    }

    printf("...ORIGINAL PKG_ID:%s\n", pkgId);
    printf("...READ     PKG_ID:%s\n", readPkgId);
    if(strcmp(pkgId, readPkgId) != 0) {
        printf("...FAIL: different pkgid. orig=%s, read=%s.\n", pkgId, readPkgId);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    _print_binary_to_hex("...ORIGINAL DEK = ", dek, sizeof(dek));
    _print_binary_to_hex("...READ     DEK = ", readDek, sizeof(readDek));
    if(_compare_binary(dek, sizeof(dek), readDek, sizeof(readDek)) != 0 ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: DEK != READ_DEK.\n");
        goto error;
    }

    ret = WAE_ERROR_NONE;
error:
    unlink(path);
    return ret;
}

int wae_tc_create_app_dek()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    unsigned char* dek = NULL;
    int dekLen = 0;

    int storedDekLen = 0;
    unsigned char* storedDek = NULL;

    remove_app_dek(pkgId);

    ret = create_app_dek(pkgId, &dek, &dekLen);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: create_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret != WAE_ERROR_NONE) {
        ret = WAE_ERROR_KEY_MANAGER;
        printf("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED  DEK = ", dek, dekLen);
    _print_binary_to_hex("...STORED   DEK = ", storedDek, storedDekLen); 
    if(_compare_binary(dek, dekLen, storedDek, storedDekLen) != 0 ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: DEK != STORED_DEK.\n");
        goto error;
    }

    remove_app_dek(pkgId);

    ret = WAE_ERROR_NONE;
error:
    if(dek != NULL)
        free(dek);
    if(storedDek != NULL)
        free(storedDek);
    return ret;
}

int wae_tc_get_create_preloaded_app_dek()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    unsigned char *dek = NULL;
    unsigned char *readDek = NULL;
    int readDekLen = 0;
    int dekLen = 0;
    char path[MAX_PATH_LEN] = {0, };

    _get_initial_value_file_path(pkgId, path);

    unlink(path);

    ret = get_preloaded_app_dek(pkgId, &readDek, &readDekLen);
    if(ret != WAE_ERROR_NO_KEY) {
        printf("...FAIL: There should be no APP DEK.  get_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = create_preloaded_app_dek(pkgId, &dek, &dekLen);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_preloaded_app_dek(pkgId, &readDek, &readDekLen);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: get_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK = ", dek, dekLen);
    _print_binary_to_hex("...READ    DEK = ", readDek, readDekLen);

    if(_compare_binary(dek, dekLen, readDek, readDekLen) != 0 ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: DEK != READ_DEK.\n");
        goto error;
    }

    unlink(path);
    ret = WAE_ERROR_NONE;
error:
    if(dek != NULL)
        free(dek);
    if(readDek != NULL)
        free(readDek);
    return ret;
}

int wae_tc_load_preloaded_app_deks()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId1 = "TEST_PKGID_1";
    unsigned char* dek1 = NULL;
    int dekLen1 = 0;
    unsigned char* readDek1 = NULL;
    int readDekLen1 = 0;
    char path1[MAX_PATH_LEN] = {0, };
    FILE *f1 = NULL;

    const char* pkgId2 = "TEST_PKGID_2";
    unsigned char* dek2 = NULL;
    int dekLen2 = 0;
    unsigned char* readDek2 = NULL;
    int readDekLen2 = 0;
    char path2[MAX_PATH_LEN] = {0, };
    FILE *f2 = NULL;

    _get_initial_value_file_path(pkgId1, path1);
    _get_initial_value_file_path(pkgId2, path2);

    // remove old test data
    remove_app_dek(pkgId1);
    remove_app_dek(pkgId2);
    unlink(path1);
    unlink(path2);

    // create 2 dek for preloaded app
    ret = create_preloaded_app_dek(pkgId1, &dek1, &dekLen1);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = create_preloaded_app_dek(pkgId2, &dek2, &dekLen2);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    // load_preloaded_app_deks
    ret = load_preloaded_app_deks();
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: load_preloaded_app_deks. ret=%d\n", ret);
        goto error;
    }

    // get_app_dek
    ret = get_app_dek(pkgId1, &readDek1, &readDekLen1);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId2, &readDek2, &readDekLen2);
    if(ret != WAE_ERROR_NONE) {
        printf("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK1 = ", dek1, dekLen1);
    _print_binary_to_hex("...READ    DEK1 = ", readDek1, readDekLen1);
    if(_compare_binary(dek1, dekLen1, readDek1, readDekLen1) != 0 ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: DEK1 != READ_DEK1.\n");
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK2 = ", dek2, dekLen2);
    _print_binary_to_hex("...READ    DEK2 = ", readDek2, readDekLen2);
    if(_compare_binary(dek2, dekLen2, readDek2, readDekLen2) != 0 ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: DEK2 != READ_DEK2.\n");
        goto error;
    }

    // check the existenace of files
    f1 = fopen(path1, "r");
    if( f1 != NULL ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: initial file still exists. path=%s\n", path1);
        goto error;
    }

    f2 = fopen(path2, "r");
    if( f2 != NULL ) {
        ret = WAE_ERROR_FILE;
        printf("...FAIL: initial file still exists. path=%s\n", path2);
        goto error;
    }
 
    // remove_app_dek
    remove_app_dek(pkgId1);
    remove_app_dek(pkgId2);

    ret = WAE_ERROR_NONE;
error:
    if(dek1 != NULL)
        free(dek1);
    if(readDek1 != NULL)
        free(readDek1);
    if(f1 != NULL)
        fclose(f1);
    if(dek2 != NULL)
        free(dek2);
    if(readDek2 != NULL)
        free(readDek2);
    if(f2 != NULL)
        fclose(f2);

    return ret;
}

int main() 
{
    RUNTC(wae_tc_get_random, "wae_tc_get_random");
    RUNTC(wae_tc_encrypt_decrypt_aes_cbc, "wae_tc_encrypt_decrypt_aes_cbc");
    RUNTC(wae_tc_get_alias, "wae_tc_get_alias");
    RUNTC(wae_tc_add_get_remove_dek, "wae_tc_add_get_remove_dek");
    RUNTC(wae_tc_initail_value, "wae_tc_initail_value");
    RUNTC(wae_tc_create_app_dek, "wae_tc_create_app_dek");
    RUNTC(wae_tc_get_create_preloaded_app_dek, "wae_tc_get_create_preloaded_app_dek");
    RUNTC(wae_tc_load_preloaded_app_deks, "wae_tc_load_preloaded_app_deks");

    return 0;
}
