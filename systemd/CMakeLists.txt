CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/systemd/webappenc-initializer.service.in
               ${CMAKE_SOURCE_DIR}/systemd/webappenc-initializer.service @ONLY)

INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/webappenc-initializer.service
    DESTINATION
    ${SYSTEMD_UNIT_DIR}
)
