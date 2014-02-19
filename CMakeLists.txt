cmake_minimum_required(VERSION 2.8)

project(CLIENTDEMO)

set(SRC_LIST client.cpp)
set(DEMO_SRC_LIST ssldemo.cpp)

message(STATUS "PROJECT_BINARY_DIR: " ${PROJECT_BINARY_DIR})
message(STATUS "PROJECT_SOURCE_DIR: " ${PROJECT_SOURCE_DIR})
message(STATUS "SRC_LIST: " ${SRC_LIST})
message(STATUS "DEMO_SRC_LIST: " ${DEMO_SRC_LIST})

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(OpenSSL)
if(OPENSSL_FOUND)
  INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
  message(STATUS "OPENSSL_INCLUDE_DIR: " ${OPENSSL_INCLUDE_DIR})
  message(STATUS "OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif()
find_package(Boost 1.54.0 COMPONENTS system)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    message(STATUS "Boost_INCLUDE_DIRS: " ${Boost_INCLUDE_DIRS})
    add_executable(demo ${SRC_LIST})
    add_executable(ssldemo ${DEMO_SRC_LIST})
    target_link_libraries(demo pthread ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
    target_link_libraries(ssldemo pthread ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
endif()

