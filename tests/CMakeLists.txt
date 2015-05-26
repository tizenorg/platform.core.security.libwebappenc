################################################################################
# for wae_tests
################################################################################

SET(TARGET_WEBAPPENC_TEST wae_tests)

SET(WEB_APP_ENC_TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/srcs/key_handler.c
    ${PROJECT_SOURCE_DIR}/srcs/crypto_service.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wae_tests.c
)

INCLUDE_DIRECTORIES(
    ${WEB_APP_ENC_DEPS_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/srcs
)

ADD_EXECUTABLE(${TARGET_WEBAPPENC_TEST} ${WEB_APP_ENC_TEST_SOURCES})


TARGET_LINK_LIBRARIES(${TARGET_WEBAPPENC_TEST}
    ${WEB_APP_ENC_DEPS_LIBRARIES}
)


INSTALL(TARGETS ${TARGET_WEBAPPENC_TEST}
    DESTINATION /usr/bin
    PERMISSIONS OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)


