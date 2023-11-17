cmake_minimum_required(VERSION 3.2)
project(SniferApp)

set(CMAKE_CXX_STANDARD 17)

set(SNIFFER_LIB_SOURCE sniffer.cpp)

add_library(sniffer_library SHARED src/snifferlib.cpp src/packetlogger.cpp)

add_library(network_interface STATIC src/MainInterface.cpp)

set(SOURCE src/main.cpp)

add_executable(SniferApp ${SOURCE})

set(LIBRARES sniffer_library network_interface)

target_link_libraries(SniferApp PRIVATE ${LIBRARES})


