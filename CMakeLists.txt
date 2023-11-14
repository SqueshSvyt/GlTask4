cmake_minimum_required(VERSION 3.2)
project(SniferApp)

set(CMAKE_CXX_STANDARD 17)

set(SNIFFER_LIB_SOURCE sniffer.cpp)

add_library(sniffer_library SHARED snifferlib.cpp filepacketlogger.cpp)

set(SOURCE main.cpp)

add_executable(SniferApp ${SOURCE})

target_link_libraries(SniferApp PRIVATE
    sniffer_library
)


