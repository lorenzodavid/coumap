set(CMAKE_C_FLAGS "-std=gnu99 -g")

include_directories(${CMAKE_COUMAP_HEADER_PATH})

add_executable(test-cmap test-cmap.c ovstest.c ../lib/command-line.c ../lib/util.c ../lib/simple_timeval.c ../lib/ovs-thread.c ../lib/ovs-rcu.c ../lib/random.c ../lib/hash.c ../lib/fat-rwlock.c)
target_link_libraries(test-cmap coumap pthread rt)
set_target_properties(test-cmap PROPERTIES COMPILE_FLAGS "-D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS")

add_executable(unit-cmap unit-cmap.c)
target_link_libraries(unit-cmap coumap pthread rt)
set_target_properties(unit-cmap PROPERTIES COMPILE_FLAGS "-D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS")
