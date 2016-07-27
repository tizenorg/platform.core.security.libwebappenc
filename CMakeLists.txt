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

############################# Check minimum CMake version #####################

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("webappenc")

SET(SO_VERSION 1)
SET(VERSION "${SO_VERSION}.0.0")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compiler flags ##################################

SET(CMAKE_C_FLAGS_PROFILING    "-g -std=c99 -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_PROFILING  "-g -std=c++0x -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_DEBUG        "-g -std=c99 -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_DEBUG      "-g -std=c++0x -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_RELEASE      "-g -std=c99 -O2")
SET(CMAKE_CXX_FLAGS_RELEASE    "-g -std=c++0x -O2")
SET(CMAKE_C_FLAGS_CCOV         "-g -std=c99 -O2 --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       "-g -std=c++0x -O2 --coverage")

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set compiler warning flags
ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")
ADD_DEFINITIONS("-DSMACK_ENABLED")
ADD_DEFINITIONS("-DSQLCIPHER_HAS_CODEC")
ADD_DEFINITIONS("-DBINDIR=\"${BINDIR}\"")

# IF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
	ADD_DEFINITIONS("-DTIZEN_DEBUG_ENABLE")
	ADD_DEFINITIONS("-DBUILD_TYPE_DEBUG")
# ENDIF (CMAKE_BUILD_TYPE MATCHES "DEBUG")

CONFIGURE_FILE(packaging/lib${PROJECT_NAME}.manifest.in lib${PROJECT_NAME}.manifest @ONLY)
CONFIGURE_FILE(packaging/lib${PROJECT_NAME}-test.manifest.in lib${PROJECT_NAME}-test.manifest @ONLY)

################# common configurations for srcs and test ######################
SET(DEPENDENTS "openssl dlog key-manager libtzplatform-config")
PKG_CHECK_MODULES(WEB_APP_ENC_DEPS
	REQUIRED
	${DEPENDENTS}
)


############################ For PC file setting  ################################
SET(PC_NAME lib${PROJECT_NAME})
SET(PC_REQUIRED ${DEPENDENTS})
SET(PC_LDFLAGS -l${PROJECT_NAME})
#SET(PC_CFLAGS -I\${includedir})

############################ Target Setting ################################
SET(TARGET_WAE ${PROJECT_NAME})
SET(TARGET_WAE_INITIALIZER wae_initializer)
SET(TARGET_WAE_ENCRYPTER wae_encrypter)
SET(TARGET_WAE_TEST wae_tests)
SET(TARGET_WAE_TEST_COMMON wae_tests_common)

############################ Add Sub Directories  ################################
ADD_SUBDIRECTORY(srcs)
ADD_SUBDIRECTORY(build)
ADD_SUBDIRECTORY(resources)
ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(tests)
ADD_SUBDIRECTORY(systemd)
