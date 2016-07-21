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

#define DUK_SIZE 16

static void _logging_openssl_err()
{
	unsigned long e = ERR_get_error();
	char buf[512] = {0, };

	ERR_error_string_n(e, buf, 511);

	WAE_SLOGE("Openssl err: %s", buf);
}

static int _get_old_duk(const char *pkg_id, raw_buffer_s **pduk)
{
	if (pkg_id == NULL || pduk == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	unsigned char salt[32];

	memset(salt, 0xFF, sizeof(salt));

	raw_buffer_s *duk = buffer_create(DUK_SIZE * 2);
	if (duk == NULL)
		return WAE_ERROR_MEMORY;

	if (PKCS5_PBKDF2_HMAC_SHA1(pkg_id, strlen(pkg_id), salt, sizeof(salt), 1,
							   duk->size, duk->buf) != 1) {
		buffer_destroy(duk);
		return WAE_ERROR_CRYPTO;
	}

	duk->size = DUK_SIZE;

	*pduk = duk;

	WAE_SLOGD("get old duk of length: %d", duk->size);

	return WAE_ERROR_NONE;
}

static int _get_old_iv(const raw_buffer_s *src, raw_buffer_s **piv)
{
	if (!is_buffer_valid(src) || piv == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	raw_buffer_s *iv = buffer_create(SHA_DIGEST_LENGTH);
	if (iv == NULL)
		return WAE_ERROR_MEMORY;

	if (EVP_Digest(src->buf, src->size, iv->buf, &iv->size, EVP_sha1(), NULL) != 1) {
		buffer_destroy(iv);
		return WAE_ERROR_CRYPTO;
	}

	*piv = iv;

	WAE_SLOGD("get old iv of length: %d", iv->size);

	return WAE_ERROR_NONE;
}

static int _decrypt(const crypto_element_s *ce, const raw_buffer_s *data,
					raw_buffer_s **pdecrypted)
{
	if (!is_crypto_element_valid(ce) || !is_buffer_valid(data) || pdecrypted == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	if (ce->dek->size != DUK_SIZE || ce->iv->size < DUK_SIZE) {
		WAE_SLOGE("Invalid key or iv size for decrypt by aes_128_cbc algorithm. "
				  "key should be 16 bytes and iv should be bigger than 16 bytes");
		return WAE_ERROR_INVALID_PARAMETER;
	}

	const struct evp_cipher_st *algo = EVP_aes_128_cbc();

	int in_len = data->size;
	int out_len = 0;
	int final_len = 0;

	raw_buffer_s *decrypted = buffer_create(
			(in_len / algo->block_size + 1) * algo->block_size);

	if (decrypted == NULL)
		return WAE_ERROR_MEMORY;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	int ret = WAE_ERROR_NONE;

	if (EVP_CipherInit(&ctx, algo, ce->dek->buf, ce->iv->buf, 0) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_CIPHER_CTX_set_padding(&ctx, 1) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_CipherUpdate(&ctx, decrypted->buf, &out_len, data->buf, in_len) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_CipherFinal(&ctx, decrypted->buf + out_len, &final_len) != 1) {
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	decrypted->size = out_len + final_len;

	*pdecrypted = decrypted;

error:
	EVP_CIPHER_CTX_cleanup(&ctx);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(decrypted);

	return ret;
}

int get_old_ss_crypto_element(const char *pkg_id, crypto_element_s **pce)
{
	if (pkg_id == NULL || pce == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	raw_buffer_s *duk = NULL;
	raw_buffer_s *iv = NULL;
	crypto_element_s *ce = NULL;

	int ret = _get_old_duk(pkg_id, &duk);
	if (ret != WAE_ERROR_NONE)
		return ret;

	ret = _get_old_iv(duk, &iv);
	if (ret != WAE_ERROR_NONE)
		goto error;

	ce = crypto_element_create(duk, iv);
	if (ce == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	ce->is_migrated_app = true;

	*pce = ce;

	return WAE_ERROR_NONE;

error:
	buffer_destroy(duk);
	buffer_destroy(iv);

	return ret;
}

int decrypt_by_old_ss_algo(const crypto_element_s *ce, const raw_buffer_s *encrypted,
						   raw_buffer_s **pdecrypted)
{
	if (!is_crypto_element_valid(ce) || !is_buffer_valid(encrypted) || pdecrypted == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	int ret = _decrypt(ce, encrypted, pdecrypted);

	switch (ret) {
	case WAE_ERROR_CRYPTO:
		WAE_SLOGE("decrypt with old ss algo failed with crypto error below.");
		_logging_openssl_err();
		break;
	case WAE_ERROR_NONE:
		WAE_SLOGI("decrypt with old ss algo success!");
		break;
	default:
		WAE_SLOGE("decrypt with old ss algo failed! ret(%d)", ret);
		break;
	}

	return ret;
}
