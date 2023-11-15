cmake_minimum_required(VERSION 3.2)
project(SniferApp)

set(CMAKE_CXX_STANDARD 17)

set(SNIFFER_LIB_SOURCE sniffer.cpp)

add_library(sniffer_library STATIC snifferlib.cpp filepacketlogger.cpp)

add_library(network_interface SHARED NetworkInterface.cpp)

set(SOURCE main.cpp)

add_executable(SniferApp ${SOURCE})

set(LIBRARES sniffer_library network_interface)

target_link_libraries(SniferApp PRIVATE ${LIBRARES})


