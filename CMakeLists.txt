# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

SET(CMAKE_C_FLAGS_PROFILING    "-g -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_PROFILING  "-g -std=c++0x -O0 -pg -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_DEBUG        "-g -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_CXX_FLAGS_DEBUG      "-g -std=c++0x -O0 -ggdb -Wp,-U_FORTIFY_SOURCE")
SET(CMAKE_C_FLAGS_RELEASE      "-g -O2")
SET(CMAKE_CXX_FLAGS_RELEASE    "-g -std=c++0x -O2")
SET(CMAKE_C_FLAGS_CCOV         "-g -O2 --coverage")
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

# IF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
    ADD_DEFINITIONS("-DTIZEN_DEBUG_ENABLE")
    ADD_DEFINITIONS("-DBUILD_TYPE_DEBUG")
# ENDIF (CMAKE_BUILD_TYPE MATCHES "DEBUG")
 
################# common configurations for srcs and test ######################
SET(DEPENDENTS "openssl dlog key-manager")
PKG_CHECK_MODULES(WEB_APP_ENC_DEPS
    ${DEPENDENTS}
    REQUIRED
)


############################ For PC file setting  ################################
SET(PC_NAME ${PROJECT_NAME})
SET(PC_REQUIRED ${DEPENDENTS})
SET(PC_LDFLAGS -l${PROJECT_NAME})
#SET(PC_CFLAGS -I\${includedir})
 

############################ Target Setting ################################
SET(TARGET_WEBAPPENC ${PROJECT_NAME})
SET(TARGET_WAE_INITIALIZER wae_initializer)
SET(TARGET_WAE_ENCRYPTER wae_encrypter)
SET(TARGET_WEBAPPENC_TEST wae_tests)

############################ Add Sub Directories  ################################
SET(TARGET_WEBAPPENC ${PROJECT_NAME})
ADD_SUBDIRECTORY(srcs)
ADD_SUBDIRECTORY(build)
ADD_SUBDIRECTORY(resources)
ADD_SUBDIRECTORY(include)
ADD_SUBDIRECTORY(tests)
ADD_SUBDIRECTORY(systemd)


