# Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Kyungwook Tak (k.tak@samsung.com)
# @brief       cmake for test program
#
ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK)

#### test common library ####
PKG_CHECK_MODULES(${TARGET_WAE_TEST_COMMON}_DEP
	REQUIRED
)

SET(${TARGET_WAE_TEST_COMMON}_SRCS
	colour_log_formatter.cpp
	test-common.cpp
)

INCLUDE_DIRECTORIES(
	SYSTEM
	${${TARGET_WAE_TEST_COMMON}_DEP_INCLUDE_DIRS}
)

INCLUDE_DIRECTORIES(
	.
)

ADD_LIBRARY(${TARGET_WAE_TEST_COMMON} SHARED ${${TARGET_WAE_TEST_COMMON}_SRCS})

SET_TARGET_PROPERTIES(${TARGET_WAE_TEST_COMMON}
	PROPERTIES
		COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=default"
)

TARGET_LINK_LIBRARIES(${TARGET_WAE_TEST_COMMON}
	${${TARGET_WAE_TEST_COMMON}_DEP_LIBRARIES}
	-lboost_unit_test_framework
)

INSTALL(TARGETS ${TARGET_WAE_TEST_COMMON} DESTINATION ${LIBDIR})

#### main test program ####
PKG_CHECK_MODULES(${TARGET_WAE_TEST}_DEP
	REQUIRED
)

SET(${TARGET_WAE_TEST}_SRCS
	main.cpp
	non-normals.cpp
	normals.cpp
	internals.cpp
	test-helper.cpp
)

INCLUDE_DIRECTORIES(
	SYSTEM
	${${TARGET_WAE_TEST}_DEP_INCLUDE_DIRS}
)

INCLUDE_DIRECTORIES(
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/srcs
	.
)

ADD_EXECUTABLE(${TARGET_WAE_TEST} ${${TARGET_WAE_TEST}_SRCS})

TARGET_LINK_LIBRARIES(${TARGET_WAE_TEST}
	${${TARGET_WAE_TEST}_DEP_LIBRARIES}
	${TARGET_WAE_TEST_COMMON}
	${TARGET_WAE}
	-lboost_unit_test_framework
	-ldl
)


INSTALL(TARGETS ${TARGET_WAE_TEST}
	DESTINATION ${BINDIR}
	PERMISSIONS
		OWNER_READ
		OWNER_WRITE
		OWNER_EXECUTE
		GROUP_READ
		GROUP_EXECUTE
		WORLD_READ
		WORLD_EXECUTE
)
