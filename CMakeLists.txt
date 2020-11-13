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

set(HOME $ENV{HOME})
message(HOME: ${HOME})

include_directories(.)
include_directories(utils)
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

if ("${PROFILE}" STREQUAL 1)
    message("Profiling enabled")
    SET(PROFILE_CXX_FLAGS  " -pg ")
    message("PROFILE_CXX_FLAGS ${CMAKE_CXX_FLAGS}")
    set("CMAKE_CXX_FLAGS_DEBUG is ${CMAKE_CXX_FLAGS_DEBUG} ${PROFILE_CXX_FLAGS}")
    set("CMAKE_CXX_FLAGS_RELWITHDEBINFO is ${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${PROFILE_CXX_FLAGS}")
    set("CMAKE_CXX_FLAGS_RELEASE is ${CMAKE_CXX_FLAGS_RELEASE} ${PROFILE_CXX_FLAGS}")
endif()

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})

    if ("${PROBER}" STREQUAL 1)
        if("${PF_RING}" STREQUAL 1)
            message(STATUS "PF_RING Enabled")
            add_definitions(-DPF_RING_ENABLED)
            add_executable(Heartbeat main.cpp heartbeat_t.cpp patricia.cpp classic_sender_t.cpp sniffer_t.cpp pfring_sender_t.cpp utils/timing_utils.cpp probing_options_t.cpp
                    utils/network_utils_t.cpp utils/packets_utils.cpp utils/parameters_utils_t.cpp)
            target_link_libraries(Heartbeat PUBLIC tins cperm z pthread pfring ${Boost_LIBRARIES})
        else()
            message(STATUS "PF_RING Disabled")
#            add_definitions(-DPF_RING_ENABLED=0)
            add_executable(Heartbeat main.cpp heartbeat_t.cpp patricia.cpp classic_sender_t.cpp sniffer_t.cpp utils/timing_utils.cpp probing_options_t.cpp
                    utils/network_utils_t.cpp utils/packets_utils.cpp utils/parameters_utils_t.cpp)
            target_link_libraries(Heartbeat PUBLIC tins cperm z pthread ${Boost_LIBRARIES})
        endif()

    endif()
endif()
