set(CMAKE_C_FLAGS "-std=gnu99 -g")

add_library(coumap cmap.c util.c simple_timeval.c ovs-thread.c ovs-rcu.c random.c hash.c shash.c guarded-list.c seq.c latch-unix.c socket-util-unix.c socket-util.c dynamic-string.c fatal-signal.c byteq.c poll-loop.c  hmap.c sset.c signals.c entropy.c)
set_target_properties(coumap PROPERTIES COMPILE_FLAGS "-D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS")
target_link_libraries(coumap pthread rt ssl)

add_library(hash hash.c)

add_subdirectory(test)
add_subdirectory(openvswitch)

FILE(GLOB HEADERFILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.h)
install(FILES ${HEADERFILES} DESTINATION ${CMAKE_COUMAP_HEADER_PATH}/coumap)
install(TARGETS coumap EXPORT ${CMAKE_COUMAP_INSTALL_TARGETS} DESTINATION ${CMAKE_COUMAP_LIB_PATH})
