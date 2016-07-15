################################################################################
# for libwebappenc.so
################################################################################

SET(WEB_APP_ENC_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/web_app_enc.c
	${CMAKE_CURRENT_SOURCE_DIR}/key_handler.c
	${CMAKE_CURRENT_SOURCE_DIR}/crypto_service.c
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
