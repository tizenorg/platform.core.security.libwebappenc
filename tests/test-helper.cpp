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
 * @file        test-helper.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 */
#include "test-helper.h"

#include <cstring>
#include <vector>

#include "key_handler.h"
#include "crypto_service.h"
#include "types.h"
#include "key_manager.h"

#include "test-common.h"

/*
namespace {

using CryptoElemRaii = std::unique_ptr<crypto_element_s, void(*)(crypto_element_s *)>;

CryptoElemRaii createCryptoElemRaii(crypto_element_s *ce)
{
	return CryptoElemRaii(ce, crypto_element_destroy);
}

}
*/

namespace Wae {
namespace Test {

void add_get_remove_ce(wae_app_type_e app_type)
{
	const char *pkg_id = "TEST_PKG_ID";

	const crypto_element_s *ce = nullptr;
	int tmp = create_app_ce(pkg_id, app_type, &ce);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to create_app_ce. ec: " << tmp);

	const crypto_element_s *stored_ce = nullptr;
	tmp = get_app_ce(pkg_id, app_type, true, &stored_ce);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to get_app_ce. ec: " << tmp);

	BOOST_REQUIRE_MESSAGE(ce == stored_ce,
		"ce(" << ce << ") and cached ce(" << stored_ce << ") pointer addr is different!");

	tmp = remove_app_ce(pkg_id, app_type);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to remove_app_ce. ec: " << tmp);

	if (app_type == WAE_DOWNLOADED_GLOBAL_APP) {
		tmp = get_app_ce(pkg_id, app_type, true, &stored_ce);
		BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE && stored_ce->is_migrated_app,
				"when getting app ce which is there isn't, it should be migrated case! "
				"ret("<< tmp << ") and is_migrated_app(" << stored_ce->is_migrated_app << ")");
	} else {
		tmp = get_app_ce(pkg_id, app_type, false, &stored_ce);
		BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NO_KEY,
				"removed app ce is still remaining. ret(" << tmp << ")");
	}
}

void create_app_ce(wae_app_type_e app_type)
{
	const char *pkg_id = "TEST_PKG_ID";

	remove_app_ce(pkg_id, app_type);

	const crypto_element_s *ce = nullptr;

	int tmp = create_app_ce(pkg_id, app_type, &ce);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to create_app_ce. ec: " << tmp);

	const crypto_element_s *stored_ce = nullptr;
	tmp = get_app_ce(pkg_id, app_type, false, &stored_ce);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to get_app_ce. ec: " << tmp);

	BOOST_REQUIRE_MESSAGE(ce == stored_ce,
		"ce(" << ce << ") and cached ce(" << stored_ce << ") pointer addr is different!");

	tmp = remove_app_ce(pkg_id, app_type);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to remove_app_ce. ec: " << tmp);
}

void encrypt_decrypt_web_app(wae_app_type_e app_type)
{
	const char *pkg_id1 = "testpkg_for_normal";
	const char *pkg_id2 = "testpkg_for_global";
	const char *pkg_id3 = "testpkg_for_preloaded";

	const char *pkg_id = nullptr;
	switch (app_type) {
	case WAE_DOWNLOADED_NORMAL_APP:
		pkg_id = pkg_id1;
		break;

	case WAE_DOWNLOADED_GLOBAL_APP:
		pkg_id = pkg_id2;
		break;

	case WAE_PRELOADED_APP:
	default:
		pkg_id = pkg_id3;
		break;
	}

	// remove old test data
	wae_remove_app_dek(pkg_id, app_type);

	if (app_type == WAE_PRELOADED_APP)
		clear_app_deks_loaded_from_key_manager();

	std::vector<unsigned char> plaintext = {
		'a', 'b', 'c', 'a', 'b', 'c', 'x', 'y',
		'o', 'q', '2', 'e', 'v', '0', '1', 'x'
	};

	// test for downloaded web application
	unsigned char *_encrypted = nullptr;
	size_t _enc_len = 0;
	int tmp = wae_encrypt_web_application(pkg_id, app_type, plaintext.data(),
										  plaintext.size(), &_encrypted, &_enc_len);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE,
			"Failed to wae_encrypt_web_application. ec: " << tmp);
	free(_encrypted);

	// encrypt test twice
	tmp = wae_encrypt_web_application(pkg_id, app_type, plaintext.data(),
									  plaintext.size(), &_encrypted, &_enc_len);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE,
			"Failed to wae_encrypt_web_application second time. ec: " << tmp);

	auto encrypted = bytearr_to_vec(_encrypted, _enc_len);
	free(_encrypted);

	_remove_app_ce_from_cache(pkg_id);

	if (app_type == WAE_PRELOADED_APP)
		load_preloaded_app_deks(true);

	unsigned char *_decrypted = nullptr;
	size_t _dec_len = 0;
	tmp = wae_decrypt_web_application(pkg_id, app_type, encrypted.data(),
									  encrypted.size(), &_decrypted, &_dec_len);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE,
			"Failed to wae_decrypt_web_application. ec: " << tmp);

	auto decrypted = bytearr_to_vec(_decrypted, _dec_len);

	BOOST_REQUIRE_MESSAGE(plaintext == decrypted,
		"plaintext and decrypted isn't matched! "
		"plaintext(" << bytes_to_hex(plaintext) << ") "
		"decrypted(" << bytes_to_hex(decrypted) << ")");

	tmp = wae_remove_app_dek(pkg_id, app_type);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE,
			"Failed to wae_remove_app_dek. ec: " << tmp);
}

} // namespace Test
} // namespace Wae
