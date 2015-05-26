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
 * @file        wae_tests.c
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       internal test cases for libwebappenc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "web_app_enc.h"
#include "key_handler.h"
#include "crypto_service.h"

#include <tzplatform_config.h>

static size_t tc_seq = 0;
static size_t tc_succ = 0;
static size_t tc_fail = 0;

#define FPRINTF(format, args...) fprintf(stdout, format, ##args)

static int RUNTC(int (*tc_method)(), const char* tc_name)
{
    int ret = WAE_ERROR_NONE;
    FPRINTF("[%02d:%s]started...\n", tc_seq, tc_name);
    ret = tc_method();
    if(ret == WAE_ERROR_NONE) {
        FPRINTF("[%02d:%s]ended. SUCCESS\n\n", tc_seq, tc_name);
        tc_succ++;
    } else {
        FPRINTF("[%02d:%s]ended. FAIL. error=%d\n\n", tc_seq, tc_name, ret);
        tc_fail++;
    }
    tc_seq++;
    return ret;
}

static void PRINT_TC_SUMMARY()
{
    FPRINTF("\n");
    FPRINTF("===============================================\n");
    FPRINTF(" TOTAL = %d, SUCCESS = %d, FAIL = %d\n", tc_seq, tc_succ, tc_fail);
    FPRINTF("===============================================\n");
}

void _print_binary_to_hex(const char* msg, unsigned char* bin, size_t len)
{
    size_t i = 0;
    FPRINTF("%s", msg);
    for(i=0; i<len; i++) {
        FPRINTF("%02x", bin[i]);
    }
    FPRINTF("\n");
}

int _compare_binary(const unsigned char* b1, size_t b1Len, const unsigned char* b2, size_t b2Len)
{
    size_t i = 0;
    if(b1Len != b2Len)
        return b1Len - b2Len;
    for(i=0; i<b1Len; i++) {
        if(b1[i] != b2[i])
            return b1[i] - b2[i];
    }
    return 0;
}


//=================================================================================
// tests for crypto_service.h
//=================================================================================
int wae_tc_encrypt_decrypt_app_dek()
{
    int ret = WAE_ERROR_NONE;
    unsigned char dek[32];
    unsigned char* encryptedDek = NULL;
    size_t encryptedDekLen = 0;
    unsigned char* decryptedDek = NULL;
    size_t decryptedDekLen = 0;

    const char* priKey =
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpgIBAAKCAQEA0kWtjpRO7Zh2KX2naVE/BDJdrfwK9xexfNA0MkY2VJ4J2AKM\n"
            "YTj1D1jntceryupCEHOvP3rum+WsFvPXduz9+VKnSsSqj4jcTUubtpDUGA5G79Iq\n"
            "LEPFuSBaqI8Uwkzd08pE+s30oaJDnNazMhSq8JkqBPoCCwtUs73ruE9VbtsBO/kT\n"
            "lASIAfe8nXqcJLcDQgWYhizjJw0Pi6d74oCwS2OTvQDNvsXfFnA0ZJEEYw/rZLir\n"
            "j7OHoOjz+Sh5N+1uA3Up6SPPEbHuP6L12YxqHdy7gnJXodLhvE/cR4SN9VW7+qmC\n"
            "MBjmLkBejGrEX3STS9sLI7MZHu9Y26dwuYb4+wIDAQABAoIBAQCwxqV/vc2RUGDe\n"
            "xuXM0+IvrAw37jJlw4SS0xNexMp+XxMViCbuwYy851h96azS/himbiuCKd6aL/96\n"
            "mGunbtyiFEvSvv5Jh5z2Wr9BQAcfZjla+4w7BIsg9UNifE/OfgLsQBu34xhsHtfK\n"
            "7nFehCOl/I5n+qtnD5KZPe0DWacQdwY4vEAj6YyXdb2bBg+MiwE9KVxGEIUDbklh\n"
            "Is70JXczjLZCS+lIpOKh0/lbZmBZePoUbVTtS+GvtPTpQC/aTHRkwGoEtuPEWpbL\n"
            "0Q1d6zO+vDJVLJlb5FF2haghs8IlqAxkkPjeUTNye+WktRrDQxmPu/blbxQrygfq\n"
            "Au5tBnsxAoGBAOiVtcpg32puo3Yq2Y78oboe9PuHaQP0d3DhwP3/7J0BeNslpjW7\n"
            "E1LWsVsCanxTE8XPUdFfAWgMk7lQqESN0wawGmSmWk+eQPZdjHanBaC8vh7aKjo6\n"
            "q9FdT1DKjrRi23QyDco3f3E7hvM93IAAhw1ikNu8DT19JAxtdeMh5WAZAoGBAOdw\n"
            "6neEvIFXh3RWEv2/GKVhVR8mxDqxmuFdXpOF+YWsK0Tg4uC8jm9kUGnwXgT2Mjke\n"
            "oAwYAFcRbHQQGsxy/vkV16kv4aurTE2hMpjeXCAakwV0Pi2w1f9WnDokjgORkOmc\n"
            "+QK9I8egdFPMVDfQjhLslhSUY0Eb4qcJ6q9WxfQzAoGBANSsAFybk+7oWAO3TtQW\n"
            "YXOk1vIgcYAyS/0mEKixGZS/QdlxZbf/5b17nxTO8rvX416fIftG2ixgQ7vR6us0\n"
            "m9+jq56ZFj9zP4eHJudf9h9yNo5TgwVXnMCGh/4iGbcMJgrrsfxUHu5VNiK5UCSj\n"
            "VtqAZGDoZVryUMIkXQVhezIRAoGBAN7QUIqcGbcUA24257Wu4hVlrUN+WPCAyDEr\n"
            "aL/x/ZV5eXaoYwQlw6LuGpTDOmDgfN2M5FyARuOL/LOIRaSLGXnIU4WoeUSCd8VM\n"
            "6Z9Og7bMnrpjfPEUDBH02hcH1kkNPUwLOZgva2Dm0tdSIcpSWFVTu/E4Io4uQHi8\n"
            "DVqc2ZsNAoGBAJT76ezXNSSv8hnrKqTpwgTicpqhRZ3eFQjyl4HRL26AJMKv++x8\n"
            "4/IsVIwxaHzpbN3nnCjmAHV4gX9YpxVnvYcZflC9WZeDkwNMLmPYb3Zg27EzSMfQ\n"
            "8yrfWJZo3qobipcHf1yohAt4fHk9kUKtPHEwp0xKe//rfhswLb3VCzvQ\n"
            "-----END RSA PRIVATE KEY-----";
    const char* pubKey =
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0kWtjpRO7Zh2KX2naVE/\n"
            "BDJdrfwK9xexfNA0MkY2VJ4J2AKMYTj1D1jntceryupCEHOvP3rum+WsFvPXduz9\n"
            "+VKnSsSqj4jcTUubtpDUGA5G79IqLEPFuSBaqI8Uwkzd08pE+s30oaJDnNazMhSq\n"
            "8JkqBPoCCwtUs73ruE9VbtsBO/kTlASIAfe8nXqcJLcDQgWYhizjJw0Pi6d74oCw\n"
            "S2OTvQDNvsXfFnA0ZJEEYw/rZLirj7OHoOjz+Sh5N+1uA3Up6SPPEbHuP6L12Yxq\n"
            "Hdy7gnJXodLhvE/cR4SN9VW7+qmCMBjmLkBejGrEX3STS9sLI7MZHu9Y26dwuYb4\n"
            "+wIDAQAB\n"
            "-----END PUBLIC KEY-----";

    ret = encrypt_app_dek((const unsigned char*) pubKey, strlen(pubKey),
                          dek, sizeof(dek), &encryptedDek, &encryptedDekLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: encrypt_app_dek. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = decrypt_app_dek((const unsigned char*) priKey, strlen(priKey), NULL,
                          encryptedDek, encryptedDekLen, &decryptedDek, &decryptedDekLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: decrypt_app_dek. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    _print_binary_to_hex("...ORIG DEK= ", dek, sizeof(dek));
    _print_binary_to_hex("...ENC  DEK= ", encryptedDek, encryptedDekLen);
    _print_binary_to_hex("...DEC  DEK= ", decryptedDek, decryptedDekLen);

    if(_compare_binary(dek, sizeof(dek), decryptedDek, decryptedDekLen) != 0) {
        FPRINTF("...FAIL: ORIG DEK != decrypted DEK\n");
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = WAE_ERROR_NONE;

error:
    if(encryptedDek != NULL)
        free(encryptedDek);
    if(decryptedDek != NULL)
        free(decryptedDek);

    return ret;
}

int wae_tc_encrypt_decrypt_aes_cbc()
{
    int ret = WAE_ERROR_NONE;

    unsigned char dek[32] = {0, };
    size_t keyLen = 32;
    const char* plaintext= "adbdfdfdfdfdererfdfdfererfdrerfdrer";
    size_t plaintextLen = strlen(plaintext);
    unsigned char* encrypted = NULL;
    size_t encLen = 0;
    unsigned char* decrypted = NULL;
    size_t decLen = 0;
    char decrypted_str[1024] = {0, };

    ret = _get_random(keyLen, dek);

    ret = encrypt_aes_cbc(dek, keyLen, (const unsigned char*)plaintext, plaintextLen, &encrypted, &encLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: encrypt_aes_cbc. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = decrypt_aes_cbc(dek, keyLen, encrypted, encLen, &decrypted, &decLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: decrypt_aes_cbc. ret=%d\n", ret);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    if(plaintextLen != decLen) {
        FPRINTF("...FAIL: plaintextLen(%d) != decLen(%d)\n", plaintextLen, decLen);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    memcpy(decrypted_str, decrypted, decLen);
    FPRINTF("...plaintext = %s\n", plaintext);
    FPRINTF("...decrypted = %s\n", decrypted_str);
    if(strcmp(plaintext, decrypted_str) != 0) {
        FPRINTF("...FAIL: plaintext(%s) != decrypted(%s)\n", plaintext, decrypted_str);
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

//=================================================================================
// tests for key_handler.h
//=================================================================================
int wae_tc_cache()
{
    int ret = WAE_ERROR_NONE;

    const char* pkg1 = "pkg1";
    const char* pkg2 = "pkg2";
    const char* pkg3 = "pkg3";
    const char* pkgDummy = "dummy";

    unsigned char dek1[32] = {1, };
    unsigned char dek2[32] = {2, };
    unsigned char dek3[32] = {3, };
    unsigned char* retDek = NULL;

    _initialize_cache();

    _add_app_dek_to_cache(pkg1, dek1);
    _add_app_dek_to_cache(pkg2, dek2);
    _add_app_dek_to_cache(pkg3, dek3);

    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkg1);
    if(retDek == NULL || _compare_binary(dek1, 32, retDek, 32) != 0) {
        FPRINTF("failed in cache. Diffent DEK1\n");
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }
    _print_binary_to_hex("...DEK1         : ", dek1, 32);
    _print_binary_to_hex("...Returen DEK1 : ", retDek, 32);

    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkg2);
    if(retDek == NULL || _compare_binary(dek2, 32, retDek, 32) != 0) {
        FPRINTF("failed in cache. Diffent DEK2\n");
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }
    _print_binary_to_hex("...DEK2         : ", dek2, 32);
    _print_binary_to_hex("...Returen DEK1 : ", retDek, 32);

    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkg3);
    if(retDek == NULL || _compare_binary(dek3, 32, retDek, 32) != 0) {
        FPRINTF("failed in cache. Diffent DEK3\n");
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }
    _print_binary_to_hex("...DEK3         : ", dek3, 32);
    _print_binary_to_hex("...Returen DEK3 : ", retDek, 32);

    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkgDummy);
    if(retDek != NULL) {
        FPRINTF("failed in cache. Wrong DEK_DUMMY1 returned\n");
        _print_binary_to_hex("retured wrong DEK : ", retDek, 32);
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }

    _remove_app_dek_from_cache(pkg3);
    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkg3);
    if(retDek != NULL) {
        FPRINTF("fail to remove app dek from cache\n");
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }

    _initialize_cache();

    _add_app_dek_to_cache(pkg1, dek1);

    retDek = NULL;
    retDek = _get_app_dek_from_cache(pkg2);
    if(retDek != NULL) {
        FPRINTF("failed in cache. Wrong DEK_DUMMY2 returned\n");
        _print_binary_to_hex("retured wrong DEK : ", retDek, 32);
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }

    ret = WAE_ERROR_NONE;
error:
    return ret;
}

int wae_tc_get_random()
{
    int ret = WAE_ERROR_NONE;

    size_t rand_len = 32;
    unsigned char random[32] = {0, };

    ret = _get_random(rand_len, random);

    _print_binary_to_hex("...RANDOM = ", random, sizeof(random));

    return ret;
}

int wae_tc_get_alias()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    char sys_alias[256] = {0, };

    _get_alias(pkgId, sys_alias, sizeof(sys_alias));

    FPRINTF("...pkgid=%s, system alias=%s\n", pkgId, sys_alias);

    return ret;
}

int wae_tc_add_get_remove_dek()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";

    size_t dekLen= 32;
    unsigned char dek[32] = {0, };
    size_t storedDekLen = 0;
    unsigned char* storedDek = NULL;

    ret = _get_random(dekLen, dek);

    remove_app_dek(pkgId);

    ret = _add_dek_to_key_manager(pkgId, dek, dekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: _add_dek_to_key_manager. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    if(_compare_binary(dek, dekLen, storedDek, storedDekLen) != 0 ) {
        ret = WAE_ERROR_KEY_MANAGER;
        FPRINTF("...FAIL: DEK != STORED_DEK.\n");
        goto error;
    }

    ret = remove_app_dek(pkgId);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: remove_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret == WAE_ERROR_NONE) {
        ret = WAE_ERROR_UNKNOWN;
        FPRINTF("...FAIL: APP DEK still exists in key_manager.\n");
        goto error;
    }

    ret = WAE_ERROR_NONE;
error:
    if(storedDek != NULL)
        free(storedDek);

    return ret;
}

int wae_tc_get_preloaded_app_dek_file_path()
{
    int ret = WAE_ERROR_NONE;

    const char *pkgId = "test_pkg";
    const char *expectedPath = tzplatform_mkpath4(TZ_SYS_SHARE, 
                                    "wae", "app_dek", "WAE_APP_DEK_test_pkg.adek");
    char path[100];

    ret = _get_preloaded_app_dek_file_path(pkgId, path);
    FPRINTF("...expected path : %s\n", expectedPath);
    FPRINTF("...returned path : %s\n", path);

    if(ret != WAE_ERROR_NONE || strncmp(expectedPath, path, strlen(expectedPath)) != 0) {
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }
error:
    return ret;
}

int wae_tc_extract_pkg_id_from_file_name()
{
    int ret = WAE_ERROR_NONE;
    const char* fileName = "WAE_APP_DEK_test_pkg.adek";
    const char* expectedPkgId = "test_pkg";
    char pkgId[100];
 
    ret = _extract_pkg_id_from_file_name(fileName, pkgId);
    FPRINTF("...expected pkgId: %s\n", expectedPkgId);
    FPRINTF("...returned pkgId: %s\n", pkgId);

    if(ret != WAE_ERROR_NONE || strncmp(expectedPkgId, pkgId, strlen(expectedPkgId)) != 0) {
        ret = WAE_ERROR_UNKNOWN;
        goto error;
    }
error:
    return ret;

}

int wae_tc_read_write_encrypted_app_dek()
{
    int ret = WAE_ERROR_NONE;
    const char* pkgId = "write_test_pkg";
    unsigned char dek[256];
    unsigned char* readDek = NULL;
    size_t readDekLen = 0;

    ret = _write_encrypted_app_dek_to_file(pkgId, dek, sizeof(dek));
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("Fail to _write_encrypted_app_dek_to_file. pkgId=%s\n", pkgId);
        goto error;
    }

    ret = _read_encrypted_app_dek_from_file(pkgId, &readDek, &readDekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("Fail to _read_encrypted_app_dek_from_file. pkgId=%s\n", pkgId);
        goto error;
    }

    _print_binary_to_hex("...ORIG DEK= ", dek, sizeof(dek));
    _print_binary_to_hex("...READ DEK= ", readDek, readDekLen);
    if(_compare_binary(dek, sizeof(dek), readDek, readDekLen) != 0 ) {
        ret = WAE_ERROR_UNKNOWN;
        FPRINTF("...FAIL: DEK != read_DEK.\n");
        goto error;
    }

error:
    if(readDek != NULL)
        free(readDek);
    return ret;
}


int wae_tc_create_app_dek()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId = "TEST_PKG_ID";
    unsigned char* dek = NULL;
    size_t dekLen = 0;

    size_t storedDekLen = 0;
    unsigned char* storedDek = NULL;

    remove_app_dek(pkgId);

    ret = create_app_dek(pkgId, &dek, &dekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: create_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId, &storedDek, &storedDekLen);
    if(ret != WAE_ERROR_NONE) {
        ret = WAE_ERROR_KEY_MANAGER;
        FPRINTF("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED  DEK = ", dek, dekLen);
    _print_binary_to_hex("...STORED   DEK = ", storedDek, storedDekLen);
    if(_compare_binary(dek, dekLen, storedDek, storedDekLen) != 0 ) {
        ret = WAE_ERROR_FILE;
        FPRINTF("...FAIL: DEK != STORED_DEK.\n");
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

    const char* pkgId = "TEST_PKG_ID_FOR_CREATE";
    unsigned char *dek = NULL;
    unsigned char *readDek = NULL;
    size_t readDekLen = 0;
    size_t dekLen = 0;

    ret = get_preloaded_app_dek(pkgId, &readDek, &readDekLen);
    if(ret != WAE_ERROR_NO_KEY) {
        FPRINTF("...FAIL: There should be no APP DEK.  get_preloaded_app_dek. ret=%d\n", ret);
        ret = WAE_ERROR_FILE;
        goto error;
    }

    ret = create_preloaded_app_dek(pkgId, &dek, &dekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_preloaded_app_dek(pkgId, &readDek, &readDekLen);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: get_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK = ", dek, dekLen);
    _print_binary_to_hex("...READ    DEK = ", readDek, readDekLen);

    if(_compare_binary(dek, dekLen, readDek, readDekLen) != 0 ) {
        ret = WAE_ERROR_FILE;
        FPRINTF("...FAIL: DEK != READ_DEK.\n");
        goto error;
    }

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
    size_t dekLen1 = 0;
    unsigned char* readDek1 = NULL;
    size_t readDekLen1 = 0;
    char path1[MAX_PATH_LEN] = {0, };
    FILE *f1 = NULL;

    const char* pkgId2 = "TEST_PKGID_2";
    unsigned char* dek2 = NULL;
    size_t dekLen2 = 0;
    unsigned char* readDek2 = NULL;
    size_t readDekLen2 = 0;
    char path2[MAX_PATH_LEN] = {0, };
    FILE *f2 = NULL;

    _get_preloaded_app_dek_file_path(pkgId1, path1);
    _get_preloaded_app_dek_file_path(pkgId2, path2);

    // remove old test data
    remove_app_dek(pkgId1);
    remove_app_dek(pkgId2);
    unlink(path1);
    unlink(path2);

    // create 2 dek for preloaded app
    ret = create_preloaded_app_dek(pkgId1, &dek1, &dekLen1);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = create_preloaded_app_dek(pkgId2, &dek2, &dekLen2);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: create_preloaded_app_dek. ret=%d\n", ret);
        goto error;
    }

    // load_preloaded_app_deks
    ret = load_preloaded_app_deks(WAE_TRUE);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: load_preloaded_app_deks. ret=%d\n", ret);
        goto error;
    }

    // get_app_dek
    ret = get_app_dek(pkgId1, &readDek1, &readDekLen1);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    ret = get_app_dek(pkgId2, &readDek2, &readDekLen2);
    if(ret != WAE_ERROR_NONE) {
        FPRINTF("...FAIL: get_app_dek. ret=%d\n", ret);
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK1 = ", dek1, dekLen1);
    _print_binary_to_hex("...READ    DEK1 = ", readDek1, readDekLen1);
    if(_compare_binary(dek1, dekLen1, readDek1, readDekLen1) != 0 ) {
        ret = WAE_ERROR_FILE;
        FPRINTF("...FAIL: DEK1 != READ_DEK1.\n");
        goto error;
    }

    _print_binary_to_hex("...CREATED DEK2 = ", dek2, dekLen2);
    _print_binary_to_hex("...READ    DEK2 = ", readDek2, readDekLen2);
    if(_compare_binary(dek2, dekLen2, readDek2, readDekLen2) != 0 ) {
        ret = WAE_ERROR_FILE;
        FPRINTF("...FAIL: DEK2 != READ_DEK2.\n");
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


int wae_tc_encrypt_decrypt_web_application()
{
    int ret = WAE_ERROR_NONE;

    const char* pkgId1 = "testpkg_for_downloaded";
    const char* pkgId2 = "testpkg_for_preloaded";
    const char* plaintext= "adbdfdfdfdfdererfdfdfererfdrerfdrer";
    size_t plaintextLen = strlen(plaintext);
    unsigned char* encrypted = NULL;
    size_t encLen = 0;
    unsigned char* decrypted = NULL;
    size_t decLen = 0;
    char decrypted_str[1024] = {0, };

    int isPreloaded = 0; // Downloaded

    // remove old test data
    ret = wae_remove_app_dek(pkgId1);
    ret = wae_remove_app_dek(pkgId2);
    ret = _clear_app_deks_loaded();

    // test for downloaded web application
    ret = wae_encrypt_web_application(pkgId1, isPreloaded,
                                      (const unsigned char*)plaintext, plaintextLen,
                                      &encrypted, &encLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_encrypt_web_application. ret=%d\n", ret);
        goto error;
    }

    _remove_app_dek_from_cache(pkgId1);

    ret = wae_decrypt_web_application(pkgId1, isPreloaded, encrypted, encLen, &decrypted, &decLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_decrypt_web_application. ret=%d\n", ret);
        goto error;
    }

    if(plaintextLen != decLen) {
        FPRINTF("...FAIL: plaintextLen(%d) != decLen(%d)\n", plaintextLen, decLen);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    memcpy(decrypted_str, decrypted, decLen);
    FPRINTF("...plaintext(downloaded) = %s\n", plaintext);
    FPRINTF("...decrypted(downloaded) = %s\n", decrypted_str);
    if(strcmp(plaintext, decrypted_str) != 0) {
        FPRINTF("...FAIL: plaintext(%s) != decrypted(%s)\n", plaintext, decrypted_str);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = wae_remove_app_dek(pkgId1);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_remove_app_dek. ret=%d\n", ret);
        goto error;
    }


    // test for preloaded web application
    isPreloaded = 1;

    ret = wae_encrypt_web_application(pkgId2, isPreloaded,
                                      (const unsigned char*)plaintext, plaintextLen,
                                      &encrypted, &encLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_encrypt_web_application. ret=%d\n", ret);
        goto error;
    }
    // encrypt test twice
    ret = wae_encrypt_web_application(pkgId2, isPreloaded,
                                      (const unsigned char*)plaintext, plaintextLen,
                                      &encrypted, &encLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_encrypt_web_application2. ret=%d\n", ret);
        goto error;
    }

    ret = wae_decrypt_web_application(pkgId2, isPreloaded, encrypted, encLen, &decrypted, &decLen);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_decrypt_web_application. ret=%d\n", ret);
        goto error;
    }

    _remove_app_dek_from_cache(pkgId2);

    if(plaintextLen != decLen) {
        FPRINTF("...FAIL: plaintextLen(%d) != decLen(%d)\n", plaintextLen, decLen);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    memcpy(decrypted_str, decrypted, decLen);
    FPRINTF("...plaintext(preloaded) = %s\n", plaintext);
    FPRINTF("...decrypted(preloaded) = %s\n", decrypted_str);
    if(strcmp(plaintext, decrypted_str) != 0) {
        FPRINTF("...FAIL: plaintext(%s) != decrypted(%s)\n", plaintext, decrypted_str);
        ret = WAE_ERROR_CRYPTO;
        goto error;
    }

    ret = wae_remove_app_dek(pkgId2);
    if(ret != WAE_ERROR_NONE){
        FPRINTF("...FAIL: wae_remove_app_dek. ret=%d\n", ret);
        goto error;
    }

error:
    if(encrypted != NULL)
        free(encrypted);
    if(decrypted != NULL)
        free(decrypted);

    return ret;
}


int run_test_cases()
{
    RUNTC(wae_tc_encrypt_decrypt_app_dek, "wae_tc_encrypt_decrypt_app_dek");
    RUNTC(wae_tc_encrypt_decrypt_aes_cbc, "wae_tc_encrypt_decrypt_aes_cbc");
    RUNTC(wae_tc_cache, "wae_tc_cache");

    RUNTC(wae_tc_get_random, "wae_tc_get_random");
    RUNTC(wae_tc_get_alias, "wae_tc_get_alias");
    RUNTC(wae_tc_add_get_remove_dek, "wae_tc_add_get_remove_dek");
    RUNTC(wae_tc_get_preloaded_app_dek_file_path, "wae_tc_get_preloaded_app_dek_file_path");
    RUNTC(wae_tc_extract_pkg_id_from_file_name, "wae_tc_extract_pkg_id_from_file_name");
    RUNTC(wae_tc_read_write_encrypted_app_dek, "wae_tc_read_write_encrypted_app_dek");
    RUNTC(wae_tc_create_app_dek, "wae_tc_create_app_dek");
    RUNTC(wae_tc_get_create_preloaded_app_dek, "wae_tc_get_create_preloaded_app_dek");
    RUNTC(wae_tc_load_preloaded_app_deks, "wae_tc_load_preloaded_app_deks");
    RUNTC(wae_tc_encrypt_decrypt_web_application, "wae_tc_encrypt_decrypt_web_application");

    PRINT_TC_SUMMARY();
    return 0;
}

int main(void)
{
    int ret = 0;

    ret = run_test_cases();

    return ret;
}
