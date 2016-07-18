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
 * @file        ss_key_generator.c
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Restore old encryption key for removed secure-storage
 */
#include "ss_key_generator.h"

#include <string.h>
#include <openssl/hmac.h>

#include "wae_log.h"
#include "web_app_enc.h"

#define DUK_LEN 32

int get_old_duk(const char *pkgId, unsigned char **pDuk, size_t *len)
{
	unsigned char salt[32];

	memset(salt, 0xFF, sizeof(salt));

	unsigned char *duk = (unsigned char *)malloc(sizeof(unsigned char) * (DUK_LEN + 3));
	if (duk == NULL) {
		WAE_SLOGE("Failed to allocate memory for old duk.");
		return WAE_ERROR_MEMORY;
	}

	PKCS5_PBKDF2_HMAC_SHA1(pkgId, strlen(pkgId), salt, sizeof(salt), 1, DUK_LEN, duk);
	duk[DUK_LEN] = '\0';

	*pDuk = duk;
	*len = DUK_LEN;

	return WAE_ERROR_NONE;
}
