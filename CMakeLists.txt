cmake_minimum_required(VERSION 2.8)
project(coumap)
cmake_policy(VERSION 2.8.7)

set(CMAKE_COUMAP_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(CMAKE_COUMAP_HEADER_PATH "${CMAKE_COUMAP_INSTALL_PREFIX}/include")
set(CMAKE_COUMAP_LIB_PATH "${CMAKE_COUMAP_INSTALL_PREFIX}/lib")
set(CMAKE_COUMAP_BIN_PATH "${CMAKE_COUMAP_INSTALL_PREFIX}/bin")
set(CMAKE_COUMAP_CMAKE_SCRIPTS_PATH "${CMAKE_COUMAP_INSTALL_PREFIX}/cmake_scripts")
set(CMAKE_COUMAP_INSTALL_TARGETS "coumap-targets")

include_directories (${CMAKE_CURRENT_SOURCE_DIR})
include_directories (${CMAKE_CURRENT_BINARY_DIR})

# List of all subdirectories in coumap
list(APPEND COUMAP_SUBDIRS lib tests)

foreach(dir ${COUMAP_SUBDIRS})
  add_subdirectory(${dir})
  file(GLOB_RECURSE C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.c)
  file(GLOB_RECURSE H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.h)
  list(APPEND CPPLINT_C_FILES ${C_FILES})
  list(APPEND CPPLINT_H_FILES ${H_FILES})
endforeach()
