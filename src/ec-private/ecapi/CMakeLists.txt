cmake_minimum_required(VERSION 2.6)

PROJECT(ecapi C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude)
INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude/mibconstants)
INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude/oem/$ENV{PROJECT_NAME})

INCLUDE_DIRECTORIES($ENV{PROJECT_PATH}/user/thirdpty/lua/net-snmp-5.4.4/include)
INCLUDE_DIRECTORIES($ENV{PROJECT_PATH}/user/thirdpty/lua/net-snmp-5.4.4/agent/mibgroup)
#LINK_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/src/snmp)


FIND_LIBRARY(netsnmp_library netsnmp $ENV{PROJECT_PATH}/user/thirdpty/lua/net-snmp-5.4.4/snmplib/.libs)
#INCLUDE (CheckSymbolExists)
#CHECK_SYMBOL_EXISTS(SYS_getrandom syscall.h getrandom)

if ($ENV{D_MODEL_NAME} STREQUAL ECS4130_AC5)
  add_definitions(-DENDIANNESS_ADJUST)
endif()

INCLUDE(snmp/CMakeLists.txt)
INCLUDE(generic/CMakeLists.txt)

ADD_LIBRARY(ecapi SHARED ${LIB_SOURCES})
TARGET_LINK_LIBRARIES(ecapi ${netsnmp_library})
