################################################################################
# for libwebappenc.so
################################################################################

SET(TARGET_WEBAPPENC ${PROJECT_NAME})


SET(WEB_APP_ENC_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/web_app_enc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/key_handler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_service.c
)

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include
    ${WEB_APP_ENC_DEPS_INCLUDE_DIRS}
)

ADD_LIBRARY(${TARGET_WEBAPPENC} SHARED ${WEB_APP_ENC_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_WEBAPPENC} PROPERTIES
    SOVERSION ${SO_VERSION}
    VERSION ${VERSION}
)

TARGET_LINK_LIBRARIES(${TARGET_WEBAPPENC}
    pthread
    ${WEB_APP_ENC_DEPS_LIBRARIES}
)

INSTALL(TARGETS ${TARGET_WEBAPPENC}
    DESTINATION ${LIBDIR})

INSTALL(FILES ${PROJECT_SOURCE_DIR}/include/web_app_enc.h
    DESTINATION ${INCLUDEDIR})

