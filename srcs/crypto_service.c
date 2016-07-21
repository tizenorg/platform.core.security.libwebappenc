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
 * @file        crypto_service.c
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 * @version     1.0
 * @brief       provides encryption and decription operations.
 */
#include "crypto_service.h"

#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "web_app_enc.h"
#include "wae_log.h"

#define AES_256_KEY_SIZE 32

static bool __initialized = false;

void _initialize()
{
	if (!__initialized) {
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		__initialized = true;
	}
}

int encrypt_app_dek(const raw_buffer_s *pubkey, const raw_buffer_s *dek,
					raw_buffer_s **pencrypted_dek)
{
	if (!is_buffer_valid(pubkey) || !is_buffer_valid(dek) || pencrypted_dek == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	int ret = WAE_ERROR_NONE;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	raw_buffer_s *encrypted_dek = NULL;
	size_t len = 0;

	_initialize();

	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, pubkey->buf, pubkey->size);
	key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

	if (key == NULL) {
		BIO_reset(bio);
		BIO_write(bio, pubkey->buf, pubkey->size);
		key = d2i_PUBKEY_bio(bio, NULL);
	}

	if (key == NULL) {
		ret = WAE_ERROR_FILE;
		WAE_SLOGE("Failt to convert to public key.");
		goto error;
	}

	ctx = EVP_PKEY_CTX_new(key, NULL);

	if (ctx == NULL) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_CTX_new failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_encrypt_init failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_CTX_set_rsa_padding failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Determine buffer length */
	if (EVP_PKEY_encrypt(ctx, NULL, &len, dek->buf, dek->size) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_encrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if ((encrypted_dek = buffer_create(len)) == NULL) {
		WAE_SLOGE("Encrypt APP DEK Failed. OPENSSL_malloc failed");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	if (EVP_PKEY_encrypt(ctx, encrypted_dek->buf, &encrypted_dek->size, dek->buf,
						 dek->size) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_encrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	*pencrypted_dek = encrypted_dek;

error:
	if (bio != NULL)
		BIO_free(bio);

	if (key != NULL)
		EVP_PKEY_free(key);

	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(encrypted_dek);

	return ret;
}

int decrypt_app_dek(const raw_buffer_s *prikey, const char *prikey_pass,
					const raw_buffer_s *encrypted_dek, raw_buffer_s **pdek)
{
	if (!is_buffer_valid(prikey) || !is_buffer_valid(encrypted_dek) || pdek == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	int ret = WAE_ERROR_NONE;
	EVP_PKEY_CTX *ctx = NULL;
	raw_buffer_s *dek = NULL;
	size_t len = 0;

	_initialize();

	BIO *bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return WAE_ERROR_MEMORY;

	BIO_write(bio, prikey->buf, prikey->size);
	EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)prikey_pass);

	if (key == NULL) {
		BIO_reset(bio);
		BIO_write(bio, prikey->buf, prikey->size);
		key = d2i_PrivateKey_bio(bio, NULL);
	}

	if (key == NULL) {
		ret = WAE_ERROR_FILE;
		WAE_SLOGE("Failed to convert to public key.");
		goto error;
	}

	ctx = EVP_PKEY_CTX_new(key, NULL);

	if (ctx == NULL) {
		WAE_SLOGE("Decrypt APP DEK Failed. EVP_PKEY_CTX_new failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		WAE_SLOGE("Decrypt APP DEK Failed. EVP_PKEY_decrypt_init failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		WAE_SLOGE("Decrypt APP DEK Failed. EVP_PKEY_CTX_set_rsa_padding failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Determine buffer length */
	if (EVP_PKEY_decrypt(ctx, NULL, &len, encrypted_dek->buf, encrypted_dek->size) <= 0) {
		WAE_SLOGE("Decrypt APP DEK Failed. EVP_PKEY_decrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	dek = buffer_create(len);
	if (dek == NULL) {
		WAE_SLOGE("Decrypt APP DEK Failed. OPENSSL_malloc failed");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	if (EVP_PKEY_decrypt(ctx, dek->buf, &dek->size, encrypted_dek->buf,
						 encrypted_dek->size) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_decrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	*pdek = dek;

error:
	if (bio != NULL)
		BIO_free(bio);

	if (key != NULL)
		EVP_PKEY_free(key);

	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(dek);

	return ret;
}


int encrypt_aes_cbc(const crypto_element_s *ce, const raw_buffer_s *data,
					raw_buffer_s **pencrypted_data)
{
	if (!is_crypto_element_valid(ce) || !is_buffer_valid(data) || pencrypted_data == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	raw_buffer_s *encrypted_data = NULL;
	int ret = WAE_ERROR_NONE;

	_initialize();

	WAE_SLOGI("Encryption Started. size=%d", data->size);

	/* check input paramter */
	if (ce->dek->size != 32) {
		WAE_SLOGE("Encryption Failed. Invalid Key Length. key_len=%d", ce->dek->size);
		return WAE_ERROR_INVALID_PARAMETER;
	}

	// assing a enough memory for decryption.
	encrypted_data = buffer_create(data->size + 32);
	if (encrypted_data == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		WAE_SLOGE("Encryption Failed. EVP_CIPHER_CTX_new failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ce->dek->buf, ce->iv->buf) != 1) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptInit_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	len = encrypted_data->size;
	if (EVP_EncryptUpdate(ctx, encrypted_data->buf, &len, data->buf,
						  data->size) != 1) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptUpdate failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	encrypted_data->size = len;

	/* Finalise the encryption. Further encrypted data bytes may be written at
	 * this stage.
	 */
	if (EVP_EncryptFinal_ex(ctx, encrypted_data->buf + encrypted_data->size, &len) != 1) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptFinal_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	encrypted_data->size += len;

	*pencrypted_data = encrypted_data;

	WAE_SLOGI("Encryption Ended Successfully. encrypted_len: %d", encrypted_data->size);

error:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(encrypted_data);

	return ret;
}

int decrypt_aes_cbc(const crypto_element_s *ce, const raw_buffer_s *encrypted_data,
					raw_buffer_s **pdata)
{
	if (!is_crypto_element_valid(ce) || !is_buffer_valid(encrypted_data) || pdata == NULL)
		return WAE_ERROR_INVALID_PARAMETER;

	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	raw_buffer_s *data = NULL;
	int ret = WAE_ERROR_NONE;

	_initialize();

	WAE_SLOGI("Decryption Started. size=%d", encrypted_data->size);

	/* check input paramter */
	if (ce->dek->size != 32) {
		WAE_SLOGE("Decryption Failed. Invalid Key Length. key_len=%d", ce->dek->size);
		return WAE_ERROR_INVALID_PARAMETER;
	}

	// assing a enough memory for decryption.
	data = buffer_create(encrypted_data->size);
	if (data == NULL) {
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		WAE_SLOGE("Decryption Failed. EVP_CIPHER_CTX_new failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ce->dek->buf, ce->iv->buf) != 1) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptInit_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	len = data->size;
	if (EVP_DecryptUpdate(ctx, data->buf, &len, encrypted_data->buf,
						  encrypted_data->size) != 1) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptUpdate failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	data->size = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (EVP_DecryptFinal_ex(ctx, data->buf + data->size, &len) != 1) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptFinal_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	data->size += len;

	*pdata = data;

	WAE_SLOGI("Decryption Ended Successfully. decrypted_len: %d", data->size);

error:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE)
		buffer_destroy(data);

	return ret;
}
