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
 * @file        test-common.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 */
#include "test-common.h"

#include <sstream>
#include <iomanip>
#include <string>

namespace Wae {
namespace Test {

std::string bytes_to_hex(const std::vector<unsigned char> &bytes)
{
	std::stringstream ss;
	ss << std::hex;

	for (auto b : bytes)
		ss << std::setw(2) << std::setfill('0') << static_cast<int>(b);

	return ss.str();
}

std::vector<unsigned char> bytearr_to_vec(const unsigned char *bytes, size_t len)
{
	if (bytes == nullptr || len == 0)
		return std::vector<unsigned char>();

	std::vector<unsigned char> vec;

	for (size_t i = 0; i < len; ++i)
		vec.push_back(bytes[i]);

	return vec;
}

} // namespace Test
} // namespace Wae
