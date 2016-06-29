set(CMAKE_C_FLAGS "-std=gnu99")

add_executable(test_cmap test_cmap.c)
target_link_libraries(test_cmap cmap)
set_target_properties(test_cmap PROPERTIES COMPILE_FLAGS "-D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS")

# add_executable(bench_cmap bench_cmap.cc)
# target_link_libraries(bench_cmap benchmark pthread)
