cmake_minimum_required(VERSION 2.8)
project(Heartbeat)

set(CMAKE_CXX_STANDARD 17)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
message("CMAKE build type: ${CMAKE_BUILD_TYPE}")
message("CMAKE_CXX_FLAGS_DEBUG is ${CMAKE_CXX_FLAGS_DEBUG}")
message("CMAKE_CXX_FLAGS_RELWITHDEBINFO is ${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
message("CMAKE_CXX_FLAGS_RELEASE is ${CMAKE_CXX_FLAGS_RELEASE}")


#set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
#if(UNIX)
#    message("UNIX Detected, will set the header path of mysqlconnector to /usr/include/mysql-cppconn/")
#    set(FULL_PATH_TO_MYSQL_CONNECTOR_CPP_DIR_HEADERS /usr/include/mysql-cppconn/)
#endif(UNIX)
#
#if(APPLE)
#    message("MACOS Detected, will set the header path of mysqlconnector to /usr/local/mysql-connector-c++/include/")
#    set(FULL_PATH_TO_MYSQL_CONNECTOR_CPP_DIR_HEADERS /usr/local/mysql-connector-c++/include/)
#endif(APPLE)

set(HOME $ENV{HOME})
message(HOME: ${HOME})



#include_directories(${FULL_PATH_TO_MYSQL_CONNECTOR_CPP_DIR_HEADERS})
#link_directories(/usr/local/mysql-connector-c++/lib64/)

#include_directories(/usr/local/opt/mysql-client/include/)
#link_directories(/usr/local/opt/mysql-client/include/)

#find_library(MYSQLCPPCONN mysqlcppconn.7.8.0.15
#        PATHS /usr/local/mysql-connector-c++/lib64/)

include_directories(.)
include_directories(utils)
#include_directories(bits-operations)
include_directories(database)
include_directories(maths)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

link_directories(/usr/local/lib/)
find_package(Boost REQUIRED COMPONENTS program_options)


include_directories(/usr/local/include/)

if ("${LOCAL_DEBUG}" STREQUAL 1)
    add_subdirectory(libtins)
    include_directories(libtins/include)
endif()

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})

    if ("${PROBER}" STREQUAL 1)
        if("${PF_RING}" STREQUAL 1)
            message(STATUS "PF_RING Enabled")
            add_definitions(-DPF_RING_ENABLED)
            add_executable(Heartbeat main.cpp heartbeat_t.cpp patricia.cpp classic_sender_t.cpp sniffer_t.cpp pfring_sender_t.cpp utils/timing_utils.cpp probing_options_t.cpp
                    utils/network_utils_t.cpp utils/packets_utils.cpp)
            target_link_libraries(Heartbeat PUBLIC tins cperm z pthread pfring ${Boost_LIBRARIES})
        else()
            message(STATUS "PF_RING Disabled")
#            add_definitions(-DPF_RING_ENABLED=0)
            add_executable(Heartbeat main.cpp heartbeat_t.cpp patricia.cpp classic_sender_t.cpp sniffer_t.cpp utils/timing_utils.cpp probing_options_t.cpp
                    utils/network_utils_t.cpp utils/packets_utils.cpp)
            target_link_libraries(Heartbeat PUBLIC tins cperm z pthread ${Boost_LIBRARIES})
        endif()


    endif()

    message("${CENTRAL}")
    if ("${CENTRAL}" STREQUAL 1)
        message("This is the central server")
        set(CLICKHOUSE_DIR ${HOME}/clickhouse-cpp)
        message("clickhouse dir set to " ${CLICKHOUSE_DIR})

        find_library(CLICKHOUSE_LIB
                NAMES libclickhouse-cpp-lib.a libclickhouse-cpp-lib-static.a
                HINTS ${CLICKHOUSE_DIR}/build/clickhouse
                NO_DEFAULT_PATH)

        if(${CLICKHOUSE_LIB} STREQUAL CLICKHOUSE_LIB-NOTFOUND)
            message( FATAL_ERROR "Clickhouse Library not found, exiting..." )
        endif()

        find_library(LZ4_LIB
                NAMES liblz4-lib.a
                HINTS ${CLICKHOUSE_DIR}/build/contrib/lz4
                NO_DEFAULT_PATH)
        if(${LZ4_LIB} STREQUAL LZ4_LIB-NOTFOUND)
            message( FATAL_ERROR "LZ4 Library not found, exiting..." )
        endif()

        message(${LZ4_LIB})

        find_library(CITYHASH_LIB
                NAMES libcityhash-lib.a
                HINTS ${CLICKHOUSE_DIR}/build/contrib/cityhash
                NO_DEFAULT_PATH)
        message(${CITYHASH_LIB})
        if(${CITYHASH_LIB} STREQUAL CITYHASH_LIB-NOTFOUND)
            message( FATAL_ERROR "CITYHASH Library not found, exiting..." )
        endif()

        include_directories(${CLICKHOUSE_DIR})

        add_executable(Reader main_read.cpp reader_t.cpp
                probe_dto_t.cpp utils/network_utils_t.cpp
                database/clickhouse_t.cpp process_options_t.cpp utils/parameters_utils_t.cpp maths/stopping_points_t.cpp tracelink_t.cpp tracenode_t.cpp dynamics_t.cpp)
        target_link_libraries(Reader PUBLIC pthread tins ${CLICKHOUSE_LIB} ${LZ4_LIB} ${CITYHASH_LIB} ${Boost_LIBRARIES})

        if ("${TEST}" STREQUAL 1)
            message("Building unit tests")
            add_executable(Test unit_tests_t.cpp
                    probe_dto_t.cpp utils/network_utils_t.cpp
                    database/clickhouse_t.cpp process_options_t.cpp utils/parameters_utils_t.cpp maths/stopping_points_t.cpp)
            target_link_libraries(Test PUBLIC pthread tins ${CLICKHOUSE_LIB} ${LZ4_LIB} ${CITYHASH_LIB} ${Boost_LIBRARIES})
        endif()

#        add_executable(DynamicSnapshot main_dynamics.cpp
#                database/clickhouse_t.cpp database/clickhouse_redundancy_t.cpp database/clickhouse_dynamics_t.cpp utils/parameters_utils_t.cpp utils/network_utils_t.cpp maths/stopping_points_t.cpp dump_t.cpp tracelink_t.cpp tracenode_t.cpp dynamics_t.cpp)
#        target_link_libraries(DynamicSnapshot PUBLIC  tins pthread ${CLICKHOUSE_LIB} ${LZ4_LIB} ${CITYHASH_LIB} ${Boost_LIBRARIES} )

        add_executable(Grapher main_graph.cpp
                database/clickhouse_t.cpp utils/network_utils_t.cpp utils/parameters_utils_t.cpp database/clickhouse_graph_t.cpp maths/stopping_points_t.cpp dump_t.cpp tracelink_t.cpp tracenode_t.cpp dynamics_t.cpp )
        target_link_libraries(Grapher PUBLIC tins pthread ${CLICKHOUSE_LIB} ${LZ4_LIB} ${CITYHASH_LIB} ${Boost_LIBRARIES} )

#        add_executable(Diamonds main_diamonds.cpp
#                diamond_t.cpp database/clickhouse_t.cpp utils/network_utils_t.cpp utils/parameters_utils_t.cpp database/clickhouse_diamonds_t.cpp maths/stopping_points_t.cpp dump_t.cpp tracelink_t.cpp tracenode_t.cpp dynamics_t.cpp )
#        target_link_libraries(Grapher PUBLIC tins pthread ${CLICKHOUSE_LIB} ${LZ4_LIB} ${CITYHASH_LIB} ${Boost_LIBRARIES} )



    endif()
endif()

#SET(PROJ_LIB_DIR /usr/local/mysql-connector-c++/lib64/)
## set @rpaths for libraries to link against
#SET(CMAKE_SKIP_BUILD_RPATH  FALSE)
#SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
#SET(CMAKE_INSTALL_RPATH "${PROJ_LIB_DIR}")
#SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
