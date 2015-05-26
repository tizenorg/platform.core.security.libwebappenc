################################################################################
# for resource install
################################################################################

INSTALL(FILES 
    ${PROJECT_SOURCE_DIR}/resources/WAE_APP_DEK_KEK_PublicKey.pem
    ${PROJECT_SOURCE_DIR}/resources/WAE_APP_DEK_KEK_PrivateKey.pem
    DESTINATION /usr/share/wae/
    PERMISSIONS OWNER_READ
    OWNER_WRITE
)

INSTALL(FILES 
    ${PROJECT_SOURCE_DIR}/resources/README_APP_DEK
    DESTINATION /usr/share/wae/app_dek
    PERMISSIONS OWNER_READ
    OWNER_WRITE
)

