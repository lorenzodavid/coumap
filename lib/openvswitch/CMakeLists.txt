FILE(GLOB HEADERFILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)
install(FILES ${HEADERFILES} DESTINATION ${CMAKE_COUMAP_HEADER_PATH}/coumap/openvswitch)
