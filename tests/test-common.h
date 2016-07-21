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
 * @file        test-common.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 */
#pragma once

#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_log.hpp>
#include <boost/test/results_reporter.hpp>

#include "colour_log_formatter.h"

#include "types.h"

/* fixtures should be declared on outside of namespace */
struct TestConfig {
	TestConfig()
	{
		boost::unit_test::unit_test_log.set_threshold_level(boost::unit_test::log_test_units);
		boost::unit_test::results_reporter::set_level(boost::unit_test::SHORT_REPORT);
		boost::unit_test::unit_test_log.set_formatter(new Wae::Test::colour_log_formatter);

		BOOST_TEST_MESSAGE("run test program with --run_test=SYSTEM on sdb root turned ON");
		BOOST_TEST_MESSAGE("run test program with --run_test=USER   on sdb root turned OFF");
	}
};

namespace Wae {
namespace Test {

std::string bytes_to_hex(const std::vector<unsigned char> &bytes);
std::string bytes_to_hex(const unsigned char *ptr, size_t len);
std::string bytes_to_hex(const raw_buffer_s *rb);
std::vector<unsigned char> bytearr_to_vec(const unsigned char *ptr, size_t len);
std::vector<unsigned char> bytearr_to_vec(const raw_buffer_s *);

} // namespace Test
} // namespace Wae
