cmake_minimum_required(VERSION 2.6)

PROJECT(ucentral-client C)
SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "-Wl,--copy-dt-needed-entries")
SET(LDFLAGS -fopenmp -Wl,--copy-dt-needed-entries)

INCLUDE_DIRECTORIES(src/include)
INCLUDE_DIRECTORIES(../)
INCLUDE_DIRECTORIES(../curl/include)
INCLUDE_DIRECTORIES(../libwebsockets/include)
INCLUDE_DIRECTORIES(../openssl/include)
INCLUDE_DIRECTORIES(ucentral-client/include)
INCLUDE_DIRECTORIES(ucentral-client)

INCLUDE_DIRECTORIES(src/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_LIST_DIR}/../ecapi/include)
INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude)
INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude/mibconstants)
INCLUDE_DIRECTORIES($ENV{SOURCE_PATH}/sysinclude/oem/$ENV{PROJECT_NAME})
INCLUDE_DIRECTORIES($ENV{PROJECT_PATH}/user/thirdpty/lua/net-snmp-5.4.4/include)

add_definitions(-DPLAT_EC)

if ($ENV{D_MODEL_NAME} STREQUAL ECS4130_AC5) 
  add_definitions(-DENDIANNESS_ADJUST)
  add_definitions(-DNOT_SUPPORT_CAP_2500)
  add_definitions(-DNOT_SUPPORT_NTP_DOMAIN_NAME)
  add_definitions(-DSYSTEM_OID="1.3.6.1.4.1.259.10.1.55.")
elseif ($ENV{D_MODEL_NAME} STREQUAL ECS4125_10P)
  add_definitions(-DSYSTEM_OID="1.3.6.1.4.1.259.10.1.57.")
else()
  message(FATAL_ERROR "not support $ENV{D_MODEL_NAME}")
endif()

INCLUDE(ucentral-client/CMakeLists.txt)
INCLUDE(ucentral-client/platform/ec/CMakeLists.txt)

FIND_LIBRARY(cjson cjson ../cjson)
FIND_LIBRARY(curl curl ../curl/lib)
FIND_LIBRARY(openssl ssl ../openssl)
FIND_LIBRARY(websockets websockets ../libwebsockets/lib)
FIND_LIBRARY(crypto crypto ../openssl)

FIND_LIBRARY(ecapi_library ecapi ../ecapi/build)
FIND_LIBRARY(netsnmp_library netsnmp $ENV{PROJECT_PATH}/user/thirdpty/lua/net-snmp-5.4.4/snmplib/.libs)

ADD_EXECUTABLE(ucentral-client ${UC_SOURCES} ${PLAT_SOURCES})

TARGET_LINK_LIBRARIES(ucentral-client ${cjson} ${curl} ${openssl} ${crypto} ${websockets} ${netsnmp_library} ${ecapi_library})
