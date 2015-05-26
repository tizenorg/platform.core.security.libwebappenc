################################################################################
# for resource install
################################################################################

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/resources/WAE_APPDEK_KEK_PublicKey.pem
    ${PROJECT_SOURCE_DIR}/resources/WAE_APPDEK_KEK_PrivateKey.pem
    DESTINATION ${TZ_SYS_SHARE}/wae/app_dek/
    PERMISSIONS OWNER_READ
    OWNER_WRITE
)

