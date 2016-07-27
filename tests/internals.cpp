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
 * @file        internals.cpp
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 *              Kyungwook Tak (k.tak@samsung.com)
 * @version     2.0
 * @brief       internal functions test
 */
#include "web_app_enc.h"

#include <string>
#include <cstring>
#include <unistd.h>

#include <boost/test/unit_test.hpp>

#include "key_handler.h"
#include "crypto_service.h"

#include "test-common.h"

namespace {

using rb_raii = std::unique_ptr<raw_buffer_s, void(*)(raw_buffer_s *)>;
using ce_raii = std::unique_ptr<crypto_element_s, void(*)(crypto_element_s *)>;
using map_raii = std::unique_ptr<crypto_element_map_s, void(*)(crypto_element_map_s *)>;

inline rb_raii _safe(raw_buffer_s *ptr)
{
	return rb_raii(ptr, buffer_destroy);
}

inline ce_raii _safe(crypto_element_s *ptr)
{
	return ce_raii(ptr, crypto_element_destroy);
}

inline map_raii _safe(crypto_element_map_s *ptr)
{
	return map_raii(ptr, crypto_element_map_destroy);
}

crypto_element_s *_create_ce(void)
{
	raw_buffer_s *dek = buffer_create(32);
	raw_buffer_s *iv = buffer_create(16);
	crypto_element_s *ce = crypto_element_create(dek, iv);

	if (ce == nullptr) {
		buffer_destroy(dek);
		buffer_destroy(iv);
	} else if (_get_random(ce->dek) != WAE_ERROR_NONE) {
		crypto_element_destroy(ce);
		ce = nullptr;
	} else if (_get_random(ce->iv) != WAE_ERROR_NONE) {
		crypto_element_destroy(ce);
		ce = nullptr;
	}

	BOOST_REQUIRE(ce != nullptr);

	return ce;
}

}

BOOST_AUTO_TEST_SUITE(SYSTEM)

BOOST_AUTO_TEST_SUITE(INTERNALS)

BOOST_AUTO_TEST_CASE(encrypt_decrypt_app_dek)
{
	const char *private_key =
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

	const char *public_key =
		"-----BEGIN PUBLIC KEY-----\n"
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0kWtjpRO7Zh2KX2naVE/\n"
		"BDJdrfwK9xexfNA0MkY2VJ4J2AKMYTj1D1jntceryupCEHOvP3rum+WsFvPXduz9\n"
		"+VKnSsSqj4jcTUubtpDUGA5G79IqLEPFuSBaqI8Uwkzd08pE+s30oaJDnNazMhSq\n"
		"8JkqBPoCCwtUs73ruE9VbtsBO/kTlASIAfe8nXqcJLcDQgWYhizjJw0Pi6d74oCw\n"
		"S2OTvQDNvsXfFnA0ZJEEYw/rZLirj7OHoOjz+Sh5N+1uA3Up6SPPEbHuP6L12Yxq\n"
		"Hdy7gnJXodLhvE/cR4SN9VW7+qmCMBjmLkBejGrEX3STS9sLI7MZHu9Y26dwuYb4\n"
		"+wIDAQAB\n"
		"-----END PUBLIC KEY-----";

	raw_buffer_s *dek = buffer_create(32);

	auto _raii1 = _safe(dek);

	BOOST_REQUIRE_MESSAGE(dek != nullptr && dek->size == 32, "Failed to create buffer");
	BOOST_REQUIRE_MESSAGE(_get_random(dek) == WAE_ERROR_NONE, "Failed to get random");

	raw_buffer_s pubkey;

	pubkey.buf = (unsigned char *)public_key;
	pubkey.size = strlen(public_key);

	raw_buffer_s *encrypted = nullptr;
	int ret = encrypt_app_dek(&pubkey, dek, &encrypted);

	auto _raii2 = _safe(encrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to encrypt_app_dek. ec: " << ret);

	raw_buffer_s prikey;
	prikey.buf = (unsigned char *)private_key;
	prikey.size = strlen(private_key);

	raw_buffer_s *decrypted = nullptr;
	ret = decrypt_app_dek(&prikey, nullptr, encrypted, &decrypted);

	auto _raii3 = _safe(decrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to decrypt_app_dek. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(Wae::Test::bytes_to_hex(dek) == Wae::Test::bytes_to_hex(decrypted),
			"encrypted/decrypted dek isn't valid. "
			"dek(" << Wae::Test::bytes_to_hex(dek) << ") "
			"decrypted(" << Wae::Test::bytes_to_hex(decrypted) << ")");
}

BOOST_AUTO_TEST_CASE(encrypt_decrypt_aes_cbc)
{
	raw_buffer_s *data = buffer_create(16);

	auto _raii1 = _safe(data);

	BOOST_REQUIRE_MESSAGE(data != nullptr && data->size == 16, "Failed to create buffer");

	crypto_element_s *ce = _create_ce();

	auto _raii2 = _safe(ce);

	raw_buffer_s *encrypted = nullptr;
	int ret = encrypt_aes_cbc(ce, data, &encrypted);

	auto _raii3 = _safe(encrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to encrypt_aes_cbc. ec: " << ret);

	raw_buffer_s *decrypted = nullptr;
	ret = decrypt_aes_cbc(ce, encrypted, &decrypted);

	auto _raii4 = _safe(decrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to decrypt_aes_cbc. ec: " << ret);
	BOOST_REQUIRE_MESSAGE(Wae::Test::bytes_to_hex(data) == Wae::Test::bytes_to_hex(decrypted),
			"decrypted plaintext isn't valid. "
			"plaintext(" << Wae::Test::bytes_to_hex(data) << ") "
			"decrypted(" << Wae::Test::bytes_to_hex(decrypted) << ")");
}

BOOST_AUTO_TEST_CASE(cache)
{
	const char *pkg1 = "pkg1";
	const char *pkg2 = "pkg2";
	const char *pkg3 = "pkg3";
	const char *pkgDummy = "dummy";

	auto ce1 = _create_ce();
	auto ce2 = _create_ce();
	auto ce3 = _create_ce();

	crypto_element_map_s *map = nullptr;

	int tmp = crypto_element_map_add(&map, pkg1, ce1);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to add ce to map. ret: " << tmp);

	tmp = crypto_element_map_add(&map, pkg2, ce2);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to add ce to map. ret: " << tmp);

	tmp = crypto_element_map_add(&map, pkg3, ce3);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to add ce to map. ret: " << tmp);

	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkg1) == ce1,
			"cached ce has different address with actual.");
	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkg2) == ce2,
			"cached ce has different address with actual.");
	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkg3) == ce3,
			"cached ce has different address with actual.");
	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkgDummy) == nullptr,
			"something returned with pkg dummy from map which should be null.");

	crypto_element_map_remove(&map, pkg3);

	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkg3) == nullptr,
			"removed pkg(" << pkg3 << ") is returned from map which should be null.");

	auto ce4 = _create_ce();
	tmp = crypto_element_map_add(&map, pkg1, ce4);
	BOOST_REQUIRE_MESSAGE(tmp == WAE_ERROR_NONE, "Failed to update ce to map. ret: " << tmp);

	BOOST_REQUIRE_MESSAGE(crypto_element_map_get(map, pkg1) == ce4,
			"cached ce has different address with actual.");

	crypto_element_map_destroy(map);
}

BOOST_AUTO_TEST_CASE(cache_max)
{
	crypto_element_map_s *map = nullptr;

	for (size_t i = 0; i < MAX_MAP_ELEMENT_SIZE + 1; ++i) {
		BOOST_REQUIRE(crypto_element_map_add(&map, std::to_string(i).c_str(), _create_ce()) == WAE_ERROR_NONE);
	}

	BOOST_REQUIRE(crypto_element_map_get(map, "0") == nullptr);

	crypto_element_map_destroy(map);
}

BOOST_AUTO_TEST_CASE(read_write_encrypted_app_dek)
{
	const char *pkg_id = "write_test_pkg";

	raw_buffer_s *dek = buffer_create(256);

	auto raii1 = _safe(dek);

	BOOST_REQUIRE(dek != nullptr);
	BOOST_REQUIRE(_get_random(dek) == WAE_ERROR_NONE);

	int ret = _write_encrypted_app_dek_to_file(pkg_id, dek);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to write_encrypted_app_dek_to_file. ec: " << ret);

	raw_buffer_s *readed = nullptr;
	ret = _read_encrypted_app_dek_from_file(pkg_id, &readed);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to read_encrypted_app_dek_from_file. ec: " << ret);

	auto raii2 = _safe(readed);

	BOOST_REQUIRE_MESSAGE(Wae::Test::bytes_to_hex(dek) == Wae::Test::bytes_to_hex(readed),
			"dek isn't match after write/read file. "
			"dek(" << Wae::Test::bytes_to_hex(dek) << ") "
			"readed(" << Wae::Test::bytes_to_hex(readed) << ")");
}

BOOST_AUTO_TEST_CASE(get_create_preloaded_app_dek_1)
{
	const char *pkg_id = "TEST_PKG_ID_FOR_CREATE";

	const crypto_element_s *readed = nullptr;
	int ret = get_preloaded_app_ce(pkg_id, &readed);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NO_KEY,
			"preloaded app ce to create is already exist. ec: " << ret);

	const crypto_element_s *ce = nullptr;
	ret = create_preloaded_app_ce(pkg_id, &ce);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_ce. ec: " << ret);

	ret = get_preloaded_app_ce(pkg_id, &readed);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to get_preloaded_app_ce. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(readed == ce, "cached ce address and actual is different!");
}

BOOST_AUTO_TEST_CASE(get_create_preloaded_app_dek_2)
{
	const char *pkg_id1 = "TEST_PKGID_1";
	const char *pkg_id2 = "TEST_PKGID_2";

	char path1[MAX_PATH_LEN] = {0, };
	char path2[MAX_PATH_LEN] = {0, };
	_get_preloaded_app_dek_file_path(pkg_id1, sizeof(path1), path1);
	_get_preloaded_app_dek_file_path(pkg_id2, sizeof(path2), path2);

	// remove old test data
	remove_app_ce(0, pkg_id1, WAE_PRELOADED_APP);
	remove_app_ce(0, pkg_id2, WAE_PRELOADED_APP);
	unlink(path1);
	unlink(path2);

	// create 2 ces for preloaded app
	const crypto_element_s *ce1 = nullptr;
	int ret = create_preloaded_app_ce(pkg_id1, &ce1);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_ce. ec: " << ret);

	const crypto_element_s *ce2 = nullptr;
	ret = create_preloaded_app_ce(pkg_id2, &ce2);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_ce. ec: " << ret);

	ret = load_preloaded_app_deks(true);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to load_preloaded_app_deks. ec: " << ret);

	const crypto_element_s *readed1 = nullptr;
	ret = get_app_ce(0, pkg_id1, WAE_PRELOADED_APP, false, &readed1);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to get_app_dek. ec: " << ret);

	const crypto_element_s *readed2 = nullptr;
	ret = get_app_ce(0, pkg_id2, WAE_PRELOADED_APP, false, &readed2);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to get_app_dek. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(readed1 == ce1, "cached ce and actual address is different!");
	BOOST_REQUIRE_MESSAGE(readed2 == ce2, "cached ce and actual address is different!");

	ret = remove_app_ce(0, pkg_id1, WAE_PRELOADED_APP);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed remove app ce. ec: " << ret);

	ret = remove_app_ce(0, pkg_id2, WAE_PRELOADED_APP);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed remove app ce. ec: " << ret);
}

BOOST_AUTO_TEST_SUITE_END() // INTERNALS

BOOST_AUTO_TEST_SUITE_END() // SYSTEM
