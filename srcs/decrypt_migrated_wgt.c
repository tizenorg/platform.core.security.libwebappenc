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
 * @file        decrypt_migrated_wgt.c
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Restore old encryption key for removed secure-storage
 */
#include "decrypt_migrated_wgt.h"

#include <string.h>
#include <stdlib.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "wae_log.h"
#include "web_app_enc.h"

#define DUK_LEN 16

static void _logging_openssl_err()
{
	unsigned long e = ERR_get_error();
	char buf[512] = {0, };

	ERR_error_string_n(e, buf, 511);

	WAE_SLOGE("Openssl err: %s", buf);
}

static int _get_old_duk(const char *pkg_id, unsigned char **pduk, size_t *pduk_len)
{
	unsigned char salt[32];

	memset(salt, 0xFF, sizeof(salt));

	unsigned char *duk = (unsigned char *)malloc(sizeof(unsigned char) * ((DUK_LEN * 2) + 1));
	if (duk == NULL) {
		WAE_SLOGE("Failed to allocate memory for old duk.");
		return WAE_ERROR_MEMORY;
	}

	if (PKCS5_PBKDF2_HMAC_SHA1(pkg_id, strlen(pkg_id), salt, sizeof(salt), 1,
							   (DUK_LEN * 2), duk) != 1) {
		free(duk);
		return WAE_ERROR_CRYPTO;
	}

	duk[DUK_LEN * 2] = '\0';

	*pduk = duk;
	*pduk_len = DUK_LEN;

	WAE_SLOGD("get old duk of length: %d", *pduk_len);

	return WAE_ERROR_NONE;
}

static int _get_old_iv(const unsigned char *src, size_t src_len, unsigned char **piv, size_t *piv_len)
{
	unsigned int iv_len = SHA_DIGEST_LENGTH;
	unsigned char *iv = (unsigned char *)malloc(sizeof(unsigned char) * iv_len);
	if (iv == NULL)
		return WAE_ERROR_MEMORY;

	if (EVP_Digest(src, src_len, iv, &iv_len, EVP_sha1(), NULL) != 1) {
		free(iv);
		return WAE_ERROR_CRYPTO;
	}

	*piv = iv;
	*piv_len = iv_len;

	WAE_SLOGD("get old iv of length: %d", *piv_len);

	return WAE_ERROR_NONE;
}

static int _decrypt(const unsigned char *key, size_t key_len,
					const unsigned char *iv, size_t iv_len,
					const unsigned char *data, size_t data_len,
					unsigned char **pdecrypted, size_t *pdecrypted_len)
{
	if (key == NULL || iv == NULL || data == NULL || pdecrypted == NULL ||
			pdecrypted_len == 0)
		return WAE_ERROR_INVALID_PARAMETER;

	if (key_len != 16 || iv_len < 16) {
		WAE_SLOGE("Invalid key or iv size for decrypt by aes_128_cbc algorithm. "
				  "key should be 16 bytes and iv should be bigger than 16 bytes");
		return WAE_ERROR_INVALID_PARAMETER;
	}

	const struct evp_cipher_st *algo = EVP_aes_128_cbc();

	EVP_CIPHER_CTX ctx;

	size_t tmp_len = (data_len / algo->block_size + 1) * algo->block_size;
	int decrypted_len = 0;
	int final_len = 0;

	unsigned char *decrypted = (unsigned char *)calloc(tmp_len, 1);

	if (decrypted == NULL)
		return WAE_ERROR_MEMORY;

	EVP_CIPHER_CTX_init(&ctx);

	int ret = WAE_ERROR_NONE;

	if (EVP_CipherInit(&ctx, algo, key, iv, 0) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_CIPHER_CTX_set_padding(&ctx, 1) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_CipherUpdate(&ctx, decrypted, &decrypted_len, data, data_len) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	} else if (decrypted_len <= 0) {
		WAE_SLOGE("EVP_CipherUpdate success but returned decrypted_len(%d) <= 0",
				  decrypted_len);
		ret = WAE_ERROR_UNKNOWN;
		goto error;
	}

	if (EVP_CipherFinal(&ctx, decrypted + decrypted_len, &final_len) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	} else if (final_len <= 0) {
		WAE_SLOGE("EVP_CipherFinal success but returned final_len(%d) <= 0",
				  final_len);
		ret = WAE_ERROR_UNKNOWN;
		goto error;
	}

	*pdecrypted = decrypted;
	*pdecrypted_len = decrypted_len + final_len;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);

	return ret;
}

int decrypt_by_old_ss_algo(const char *pkg_id, const unsigned char *encrypted, size_t encrypted_len,
						   unsigned char **pdecrypted, size_t *pdecrypted_len)
{
	unsigned char *duk = NULL;
	size_t duk_len = 0;
	unsigned char *iv = NULL;
	size_t iv_len = 0;

	int ret = _get_old_duk(pkg_id, &duk, &duk_len);

	if (ret != WAE_ERROR_NONE)
		goto error;

	ret = _get_old_iv(duk, duk_len, &iv, &iv_len);

	if (ret != WAE_ERROR_NONE)
		goto error;

	ret = _decrypt(duk, duk_len, iv, iv_len, encrypted, encrypted_len, pdecrypted, pdecrypted_len);

	WAE_SLOGI("decrypt with old ss algo success of pkg: %s", pkg_id);

error:
	if (ret == WAE_ERROR_CRYPTO)
		_logging_openssl_err();

	free(duk);
	free(iv);

	return WAE_ERROR_NONE;
}
