cmake_minimum_required(VERSION 3.14)
project(memcorder)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message(FATAL_ERROR "In-tree build detected. You should do an out-of-tree build instead:\n\tcmake -B build/")
endif()

set(CMAKE_C_STANDARD 11)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
	set(CMAKE_C_FLAGS_DEBUG "-O3 -ggdb -Wall")
	set(CMAKE_C_FLAGS_RELEASE "-O3 -Wall")
	set(CMAKE_CXX_FLAGS_DEBUG "-O3 -ggdb -Wall")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall")
	add_link_options($<$<CONFIG:RELEASE>:-s>)
endif()

add_library(memcorder
	src/memcorder/buffer.c
	src/memcorder/buffer.h
	src/memcorder/channel.c
	src/memcorder/channel.h
	src/memcorder/event.c
	src/memcorder/event.h
	src/memcorder/recorder.c
	src/memcorder/recorder.h
	src/memcorder/util.c
	src/memcorder/util.h
)
target_include_directories(memcorder PUBLIC src)
target_link_libraries(memcorder Zydis)

set(gtest_force_shared_crt on)
add_subdirectory(thirdparty/googletest EXCLUDE_FROM_ALL)

add_subdirectory(thirdparty/zydis EXCLUDE_FROM_ALL)

add_executable(tests
	test/memcorder/recorder_tests.cpp
)
target_link_libraries(tests memcorder GTest::gtest_main)
add_test(NAME tests COMMAND tests)
