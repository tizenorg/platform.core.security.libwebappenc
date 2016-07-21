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
# @author
# @brief
#

################################################################################
# for libwebappenc.so
################################################################################
SET(WEB_APP_ENC_SOURCES
	web_app_enc.c
	key_handler.c
	crypto_service.c
	decrypt_migrated_wgt.c
	types.c
	key_manager.c
)

INCLUDE_DIRECTORIES(
	${PROJECT_SOURCE_DIR}/include
	${WEB_APP_ENC_DEPS_INCLUDE_DIRS}
)

ADD_LIBRARY(${TARGET_WAE} SHARED ${WEB_APP_ENC_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_WAE} PROPERTIES
	SOVERSION ${SO_VERSION}
	VERSION ${VERSION}
	COMPILE_FLAGS "-D_GNU_SOURCE"
)

TARGET_LINK_LIBRARIES(${TARGET_WAE}
	pthread
	${WEB_APP_ENC_DEPS_LIBRARIES}
)

INSTALL(TARGETS ${TARGET_WAE}
	DESTINATION ${LIBDIR})

INSTALL(FILES ${PROJECT_SOURCE_DIR}/include/web_app_enc.h
	DESTINATION ${INCLUDEDIR})


################################################################################
# for wae-initializer
################################################################################


SET(WAE_INITIALIZER_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/wae_initializer.c
)

INCLUDE_DIRECTORIES(
	${PROJECT_SOURCE_DIR}/include
	${WEB_APP_ENC_DEPS_INCLUDE_DIRS}
)

# -fPIE and -pie flag is added for ASLR
SET_SOURCE_FILES_PROPERTIES(
	${WAE_INITIALIZER_SOURCES}
	PROPERTIES
		COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE")

ADD_EXECUTABLE(${TARGET_WAE_INITIALIZER} ${WAE_INITIALIZER_SOURCES})


TARGET_LINK_LIBRARIES(${TARGET_WAE_INITIALIZER}
	pthread
	${WEB_APP_ENC_DEPS_LIBRARIES}
	${TARGET_WAE}
	-pie
)

INSTALL(TARGETS ${TARGET_WAE_INITIALIZER} DESTINATION ${BINDIR})
