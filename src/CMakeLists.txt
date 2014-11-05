cmake_minimum_required(VERSION 2.6)

PROJECT(vpnd C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES
    main.c ubus.c vpn.c config.c
    ipsec.c)

SET(LIBS
    ubox ubus uci)

IF(DEBUG)
    ADD_DEFINITIONS(-DDEBUG -g3)
    IF(NO_OPTIMIZE)
        ADD_DEFINITIONS(-O0)
    ENDIF()
ENDIF()

ADD_EXECUTABLE(vpnd ${SOURCES})

TARGET_LINK_LIBRARIES(vpnd ${LIBS})

INSTALL(TARGETS vpnd
    RUNTIME DESTINATION sbin)

