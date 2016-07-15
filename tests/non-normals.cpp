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
 * @file        non-normals.cpp
 * @author      Dongsun Lee (ds73.lee@samsung.com)
 *              Kyungwook Tak (k.tak@samsung.com)
 * @version     2.0
 * @brief       API test for preloaded/global apps
 */
#include "web_app_enc.h"

#include <boost/test/unit_test.hpp>

#include "test-helper.h"

BOOST_AUTO_TEST_SUITE(SYSTEM)

BOOST_AUTO_TEST_SUITE(GLOBAL_APP)

BOOST_AUTO_TEST_CASE(add_get_remove_dek)
{
	Wae::Test::add_get_remove_dek(WAE_DOWNLOADED_GLOBAL_APP);
}

BOOST_AUTO_TEST_CASE(create_app_dek)
{
	Wae::Test::create_app_dek(WAE_DOWNLOADED_GLOBAL_APP);
}

BOOST_AUTO_TEST_CASE(encrypt_decrypt)
{
	Wae::Test::encrypt_decrypt_web_app(WAE_DOWNLOADED_GLOBAL_APP);
}

BOOST_AUTO_TEST_SUITE_END() // GLOBAL_APP


BOOST_AUTO_TEST_SUITE(PRELOADED_APP)

BOOST_AUTO_TEST_CASE(add_get_remove_dek)
{
	Wae::Test::add_get_remove_dek(WAE_PRELOADED_APP);
}

BOOST_AUTO_TEST_CASE(create_app_dek)
{
	Wae::Test::create_app_dek(WAE_PRELOADED_APP);
}

BOOST_AUTO_TEST_CASE(encrypt_decrypt)
{
	Wae::Test::encrypt_decrypt_web_app(WAE_PRELOADED_APP);
}

BOOST_AUTO_TEST_SUITE_END() // PRELOADED_APP

BOOST_AUTO_TEST_SUITE_END() // SYSTEM
