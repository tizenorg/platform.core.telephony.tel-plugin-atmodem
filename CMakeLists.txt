CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(atmodem-plugin C)

### Global setting ###
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED glib-2.0 tcore dlog)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include/)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -O2 -Werror -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wmissing-declarations -Wredundant-decls -Wcast-align -Wall -Wno-array-bounds -Wno-empty-body -Wno-ignored-qualifiers -Wshadow -Wwrite-strings -Wswitch-default -Wno-unused-but-set-parameter -Wno-unused-but-set-variable")

ADD_DEFINITIONS("-DFEATURE_TLOG_DEBUG")
ADD_DEFINITIONS("-DTCORE_LOG_TAG=\"ATMODEM\"")

MESSAGE(${CMAKE_C_FLAGS})
MESSAGE(${CMAKE_EXE_LINKER_FLAGS})

SET(SRCS
	src/desc_at.c
	src/s_modem.c
	src/s_common.c
	src/s_network.c
	src/s_sim.c
	src/s_call.c
	src/s_ps.c
	src/s_sms.c
	src/s_ss.c
)



# library build
ADD_LIBRARY(atmodem-plugin SHARED ${SRCS})
TARGET_LINK_LIBRARIES(atmodem-plugin ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(atmodem-plugin PROPERTIES PREFIX "" OUTPUT_NAME atmodem-plugin)


# install
INSTALL(TARGETS atmodem-plugin
		LIBRARY DESTINATION lib/telephony/plugins/modems)

INSTALL(FILES ${CMAKE_SOURCE_DIR}/res/wiki_mcc_mnc_oper_list.sql DESTINATION /tmp RENAME mcc_mnc_oper_list.sql)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/LICENSE DESTINATION /usr/share/license RENAME tel-plugin-atmodem)
