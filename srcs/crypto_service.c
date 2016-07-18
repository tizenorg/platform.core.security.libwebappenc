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

static unsigned char AES_CBC_IV[16] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x08, 0x39, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static bool __initialized = false;

void _initialize()
{
	if (!__initialized) {
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		__initialized = true;
	}
}

int encrypt_app_dek(const unsigned char *pubkey, size_t pubkey_len,
					const unsigned char *dek, size_t dek_len,
					unsigned char **pencrypted_dek, size_t *pencrypted_dek_len)
{
	int ret = WAE_ERROR_NONE;
	EVP_PKEY *key = NULL;
	BIO *bio = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *out = NULL;
	size_t outLen = 0;

	_initialize();

	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, pubkey, pubkey_len);
	key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

	if (key == NULL) {
		BIO_reset(bio);
		BIO_write(bio, pubkey, pubkey_len);
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
	if (EVP_PKEY_encrypt(ctx, NULL, &outLen, dek, dek_len) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_encrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	out = OPENSSL_malloc(outLen);

	if (out == NULL) {
		WAE_SLOGE("Encrypt APP DEK Failed. OPENSSL_malloc failed");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	if (EVP_PKEY_encrypt(ctx, out, &outLen, dek, dek_len) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_encrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	*pencrypted_dek = out;
	*pencrypted_dek_len = outLen;

error:
	if (bio != NULL)
		BIO_free(bio);

	if (key != NULL)
		EVP_PKEY_free(key);

	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE && out != NULL)
		OPENSSL_free(out);

	return ret;
}

int decrypt_app_dek(const unsigned char *prikey, size_t prikey_len,
					const char *prikey_pass,
					const unsigned char *encrypted_dek, size_t encrypted_dek_len,
					unsigned char **pdecrypted_dek, size_t *pdecrypted_dek_len)
{
	int ret = WAE_ERROR_NONE;
	EVP_PKEY *key = NULL;
	BIO *bio = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char *out = NULL;
	size_t outLen = 0;

	_initialize();

	bio = BIO_new(BIO_s_mem());
	BIO_write(bio, prikey, prikey_len);
	key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)prikey_pass);

	if (key == NULL) {
		BIO_reset(bio);
		BIO_write(bio, prikey, prikey_len);
		key = d2i_PrivateKey_bio(bio, NULL);
	}

	if (key == NULL) {
		ret = WAE_ERROR_FILE;
		WAE_SLOGE("Failt to convert to public key.");
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
	if (EVP_PKEY_decrypt(ctx, NULL, &outLen, encryptedDek, encrypted_dek_len) <= 0) {
		WAE_SLOGE("Decrypt APP DEK Failed. EVP_PKEY_decrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	out = OPENSSL_malloc(outLen);

	if (out == NULL) {
		WAE_SLOGE("Decrypt APP DEK Failed. OPENSSL_malloc failed");
		ret = WAE_ERROR_MEMORY;
		goto error;
	}

	if (EVP_PKEY_decrypt(ctx, out, &outLen, encryptedDek, encrypted_dek_len) <= 0) {
		WAE_SLOGE("Encrypt APP DEK Failed. EVP_PKEY_decrypt failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	*pdecrypted_dek = out;
	*pdecrypted_dek_len = outLen;

error:
	if (bio != NULL)
		BIO_free(bio);

	if (key != NULL)
		EVP_PKEY_free(key);

	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE && out != NULL)
		OPENSSL_free(out);

	return ret;
}


int encrypt_aes_cbc(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char **pencrypted_data, size_t *pencrypted_data_len)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	unsigned char *ciphertext = NULL;
	size_t ciphertext_len;
	unsigned char *iv = AES_CBC_IV;
	int ret = WAE_ERROR_NONE;

	_initialize();

	WAE_SLOGI("Encryption Started. size=%d", data_len);

	/* check input paramter */
	if (key_len != 32) {
		WAE_SLOGE("Encryption Failed. Invalid Key Length. key_len=%d", key_len);
		return WAE_ERROR_INVALID_PARAMETER;
	}

	// assing a enough memory for decryption.
	ciphertext = (unsigned char *) malloc(data_len + 32);

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
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptInit_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_len)) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptUpdate failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		WAE_SLOGE("Encryption Failed. EVP_EncryptFinal_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	ciphertext_len += len;

	*pencrypted_data = ciphertext;
	*pencrypted_data_len = ciphertext_len;

	ret = WAE_ERROR_NONE;
	WAE_SLOGI("Encryption Ended Successfully. encrypted_len", ciphertext_len);

error:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE && ciphertext != NULL)
		free(ciphertext);

	return ret;
}

int decrypt_aes_cbc(const unsigned char *key, size_t key_len,
					const unsigned char *data, size_t data_len,
					unsigned char **pdecrypted_data, size_t *pdecrypted_data_len)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	unsigned char *plaintext = NULL;
	size_t plaintext_len;
	unsigned char *iv = AES_CBC_IV;
	int ret = WAE_ERROR_NONE;

	_initialize();

	WAE_SLOGI("Decryption Started. size=%d", data_len);

	/* check input paramter */
	if (key_len != 32) {
		WAE_SLOGE("Decryption Failed. Invalid Key Length. key_len=%d", key_len);
		return WAE_ERROR_INVALID_PARAMETER;
	}

	// assing a enough memory for decryption.
	plaintext = (unsigned char *) malloc(data_len);

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
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptInit_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, data, data_len)) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptUpdate failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		WAE_SLOGE("Decryption Failed. EVP_DecryptFinal_ex failed");
		ret = WAE_ERROR_CRYPTO;
		goto error;
	}

	plaintext_len += len;

	*pdecrypted_data = plaintext;
	*pdecrypted_data_len = plaintext_len;

	ret = WAE_ERROR_NONE;
	WAE_SLOGI("Decryption Ended Successfully. decrypted_len", plaintext_len);

error:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ret != WAE_ERROR_NONE && plaintext != NULL)
		free(plaintext);

	return ret;
}
