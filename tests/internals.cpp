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

#include <cstring>
#include <unistd.h>

#include <boost/test/unit_test.hpp>

#include "key_handler.h"
#include "crypto_service.h"

#include "test-common.h"

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

	std::vector<unsigned char> dek(32, 0);

	unsigned char *_encrypted = nullptr;
	size_t _encrypted_len = 0;
	int ret = encrypt_app_dek(reinterpret_cast<const unsigned char *>(public_key),
							  strlen(public_key), dek.data(), dek.size(), &_encrypted,
							  &_encrypted_len);
	auto encrypted = Wae::Test::bytearr_to_vec(_encrypted, _encrypted_len);
	free(_encrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to encrypt_app_dek. ec: " << ret);

	unsigned char *_decrypted = nullptr;
	size_t _decrypted_len = 0;
	ret = decrypt_app_dek(reinterpret_cast<const unsigned char *>(private_key),
						  strlen(private_key), nullptr, encrypted.data(), encrypted.size(),
						  &_decrypted, &_decrypted_len);
	auto decrypted = Wae::Test::bytearr_to_vec(_decrypted, _decrypted_len);
	free(_decrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to decrypt_app_dek. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(dek == decrypted,
			"encrypted/decrypted dek isn't valid. "
			"dek(" << Wae::Test::bytes_to_hex(dek) << ") "
			"decrypted(" << Wae::Test::bytes_to_hex(decrypted) << ")");
}

BOOST_AUTO_TEST_CASE(encrypt_decrypt_aes_cbc)
{
	std::vector<unsigned char> plaintext = {
		'a', 'b', 'c', 'a', 'b', 'c', 'x', 'y',
		'o', 'q', '2', 'e', 'v', '0', '1', 'x'
	};

	size_t dek_len = 32;
	std::vector<unsigned char> dek(dek_len, 0);

	int ret = _get_random(dek.size(), dek.data());
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to get random");

	unsigned char *_encrypted = nullptr;
	size_t _encrypted_len = 0;
	ret = encrypt_aes_cbc(dek.data(), dek.size(), plaintext.data(), plaintext.size(),
						  &_encrypted, &_encrypted_len);
	auto encrypted = Wae::Test::bytearr_to_vec(_encrypted, _encrypted_len);
	free(_encrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to encrypt_aes_cbc. ec: " << ret);

	unsigned char *_decrypted = nullptr;
	size_t _decrypted_len = 0;
	ret = decrypt_aes_cbc(dek.data(), dek.size(), encrypted.data(), encrypted.size(),
						  &_decrypted, &_decrypted_len);
	auto decrypted = Wae::Test::bytearr_to_vec(_decrypted, _decrypted_len);
	free(_decrypted);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to decrypt_aes_cbc. ec: " << ret);
	BOOST_REQUIRE_MESSAGE(plaintext == decrypted,
			"decrypted plaintext isn't valid. "
			"plaintext(" << Wae::Test::bytes_to_hex(plaintext) << ") "
			"decrypted(" << Wae::Test::bytes_to_hex(decrypted) << ")");
}

BOOST_AUTO_TEST_CASE(cache)
{
	const char *pkg1 = "pkg1";
	const char *pkg2 = "pkg2";
	const char *pkg3 = "pkg3";
	const char *pkgDummy = "dummy";

	std::vector<unsigned char> dek1(32, 1);
	std::vector<unsigned char> dek2(32, 2);
	std::vector<unsigned char> dek3(32, 3);

	_initialize_cache();

	_add_app_dek_to_cache(pkg1, dek1.data());
	_add_app_dek_to_cache(pkg2, dek2.data());
	_add_app_dek_to_cache(pkg3, dek3.data());

	size_t dek_len = 32;
	const unsigned char *_cached = _get_app_dek_from_cache(pkg1);
	auto cached = Wae::Test::bytearr_to_vec(_cached, dek_len);

	BOOST_REQUIRE_MESSAGE(cached == dek1,
			"cached dek isn't valid! "
			"dek(" << Wae::Test::bytes_to_hex(dek1) << ") "
			"cached(" << Wae::Test::bytes_to_hex(cached) << ")");

	_cached = _get_app_dek_from_cache(pkg2);
	cached = Wae::Test::bytearr_to_vec(_cached, dek_len);

	BOOST_REQUIRE_MESSAGE(cached == dek2,
			"cached dek isn't valid! "
			"dek(" << Wae::Test::bytes_to_hex(dek2) << ") "
			"cached(" << Wae::Test::bytes_to_hex(cached) << ")");

	_cached = _get_app_dek_from_cache(pkg3);
	cached = Wae::Test::bytearr_to_vec(_cached, dek_len);

	BOOST_REQUIRE_MESSAGE(cached == dek3,
			"cached dek isn't valid! "
			"dek(" << Wae::Test::bytes_to_hex(dek3) << ") "
			"cached(" << Wae::Test::bytes_to_hex(cached) << ")");

	_cached = _get_app_dek_from_cache(pkgDummy);
	if (_cached) {
		cached = Wae::Test::bytearr_to_vec(_cached, dek_len);
		BOOST_REQUIRE_MESSAGE(false,
				"wrong cached val is extracted by dummy pkg id. "
				"val(" << Wae::Test::bytes_to_hex(cached) << ")");
	}

	_remove_app_dek_from_cache(pkg3);

	_cached = _get_app_dek_from_cache(pkg3);
	if (_cached) {
		cached = Wae::Test::bytearr_to_vec(_cached, dek_len);
		BOOST_REQUIRE_MESSAGE(false,
				"app dek removed from cache but it's remained! "
				"val(" << Wae::Test::bytes_to_hex(cached) << ")");
	}

	_initialize_cache();

	_add_app_dek_to_cache(pkg1, dek1.data());

	_cached = nullptr;
	_cached = _get_app_dek_from_cache(pkg2);
	if (_cached) {
		cached = Wae::Test::bytearr_to_vec(_cached, dek_len);
		BOOST_REQUIRE_MESSAGE(false,
				"cache is initialized but something is remained! "
				"val(" << Wae::Test::bytes_to_hex(cached) << ")");
	}
}

BOOST_AUTO_TEST_CASE(read_write_encrypted_app_dek)
{
	const char *pkg_id = "write_test_pkg";

	std::vector<unsigned char> dek(256, 0);

	int ret = _write_encrypted_app_dek_to_file(pkg_id, dek.data(), dek.size());
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to write_encrypted_app_dek_to_file. ec: " << ret);

	unsigned char *_readed = nullptr;
	size_t _readed_len = 0;
	ret = _read_encrypted_app_dek_from_file(pkg_id, &_readed, &_readed_len);
	auto readed = Wae::Test::bytearr_to_vec(_readed, _readed_len);
	free(_readed);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to read_encrypted_app_dek_from_file. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(dek == readed,
			"dek isn't match after write/read file. "
			"dek(" << Wae::Test::bytes_to_hex(dek) << ") "
			"readed(" << Wae::Test::bytes_to_hex(readed) << ")");
}

BOOST_AUTO_TEST_CASE(get_create_preloaded_app_dek_1)
{
	const char *pkg_id = "TEST_PKG_ID_FOR_CREATE";

	unsigned char *_readed = nullptr;
	size_t _readed_len = 0;
	int ret = get_preloaded_app_dek(pkg_id, &_readed, &_readed_len);
	auto readed = Wae::Test::bytearr_to_vec(_readed, _readed_len);
	free(_readed);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NO_KEY,
			"preloaded app dek to create is already exist. ec: " << ret);

	unsigned char *_dek = nullptr;
	size_t _dek_len = 0;
	ret = create_preloaded_app_dek(pkg_id, &_dek, &_dek_len);
	auto dek = Wae::Test::bytearr_to_vec(_dek, _dek_len);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_dek. ec: " << ret);

	_readed = nullptr;
	ret = get_preloaded_app_dek(pkg_id, &_readed, &_readed_len);
	readed = Wae::Test::bytearr_to_vec(_readed, _readed_len);
	free(_readed);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to get_preloaded_app_dek. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(dek == readed,
			"created/loaded dek is not matched! "
			"created(" << Wae::Test::bytes_to_hex(dek) << ") "
			"loaded(" << Wae::Test::bytes_to_hex(readed) << ")");
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
	remove_app_dek(pkg_id1, WAE_PRELOADED_APP);
	remove_app_dek(pkg_id2, WAE_PRELOADED_APP);
	unlink(path1);
	unlink(path2);

	// create 2 deks for preloaded app
	unsigned char *_dek1 = nullptr;
	size_t _dek_len1 = 0;
	int ret = create_preloaded_app_dek(pkg_id1, &_dek1, &_dek_len1);
	auto dek1 = Wae::Test::bytearr_to_vec(_dek1, _dek_len1);
	free(_dek1);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_dek. ec: " << ret);

	unsigned char *_dek2 = nullptr;
	size_t _dek_len2 = 0;
	ret = create_preloaded_app_dek(pkg_id2, &_dek2, &_dek_len2);
	auto dek2 = Wae::Test::bytearr_to_vec(_dek2, _dek_len2);
	free(_dek2);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to create_preloaded_app_dek. ec: " << ret);

	ret = load_preloaded_app_deks(true);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed to load_preloaded_app_deks. ec: " << ret);

	unsigned char *_readed1 = nullptr;
	size_t _readed_len1 = 0;
	ret = get_app_dek(pkg_id1, WAE_PRELOADED_APP, &_readed1, &_readed_len1);
	auto readed1 = Wae::Test::bytearr_to_vec(_readed1, _readed_len1);
	free(_readed1);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to get_app_dek. ec: " << ret);

	unsigned char *_readed2 = nullptr;
	size_t _readed_len2 = 0;
	ret = get_app_dek(pkg_id2, WAE_PRELOADED_APP, &_readed2, &_readed_len2);
	auto readed2 = Wae::Test::bytearr_to_vec(_readed2, _readed_len2);
	free(_readed2);

	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE, "Failed to get_app_dek. ec: " << ret);

	BOOST_REQUIRE_MESSAGE(dek1 == readed1,
			"readed dek and original isn't matched! "
			"original(" << Wae::Test::bytes_to_hex(dek1) << ") "
			"readed(" << Wae::Test::bytes_to_hex(readed1) << ")");

	BOOST_REQUIRE_MESSAGE(dek2 == readed2,
			"readed dek and original isn't matched! "
			"original(" << Wae::Test::bytes_to_hex(dek2) << ") "
			"readed(" << Wae::Test::bytes_to_hex(readed2) << ")");

	ret = remove_app_dek(pkg_id1, WAE_PRELOADED_APP);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed remove app dek after used. ec: " << ret);

	ret = remove_app_dek(pkg_id2, WAE_PRELOADED_APP);
	BOOST_REQUIRE_MESSAGE(ret == WAE_ERROR_NONE,
			"Failed remove app dek after used. ec: " << ret);
}

BOOST_AUTO_TEST_SUITE_END() // INTERNALS

BOOST_AUTO_TEST_SUITE_END() // SYSTEM
