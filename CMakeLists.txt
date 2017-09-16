CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyMDNS C)

SET(PROJ_NAME "TinyMDNS")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/source/src)
SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/../tiny)

INCLUDE_DIRECTORIES(${SOURCE_ROOT}/TinyMDNS)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyBase)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyPortable)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyContainer)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyLog)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyStringUtil)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyJson)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/Netty)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUmm)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyMd5)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyThread)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyUuid)
INCLUDE_DIRECTORIES(${TINY_ROOT}/source/src/TinyWorker)

#---------------------------------------------------------------------------------------
#
# link dir
#
#---------------------------------------------------------------------------------------
LINK_DIRECTORIES(${TINY_ROOT}/target)

#-------------------------------------------------------------------------------------
# output dir
#-------------------------------------------------------------------------------------
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/target)
MESSAGE(STATUS "executable output:  ${EXECUTABLE_OUTPUT_PATH}")
MESSAGE(STATUS "library output: ${LIBRARY_OUTPUT_PATH}")

#-------------------------------------------------------------------------------------
#
# Source
#
#-------------------------------------------------------------------------------------

SET(Mdns_Header
        ${SOURCE_ROOT}/TinyMDNS/mdns_api.h
        ${SOURCE_ROOT}/TinyMDNS/MdnsConstant.h
        ${SOURCE_ROOT}/TinyMDNS/ServiceInfo.h
        ${SOURCE_ROOT}/TinyMDNS/MdnsHandler.h
        ${SOURCE_ROOT}/TinyMDNS/MdnsHandlerContext.h
        ${SOURCE_ROOT}/TinyMDNS/ServiceObserver.h
        ${SOURCE_ROOT}/TinyMDNS/ServiceListener.h
        ${SOURCE_ROOT}/TinyMDNS/codec/DnsMessageCodec.h
        ${SOURCE_ROOT}/TinyMDNS/message/DnsTypedef.h
        ${SOURCE_ROOT}/TinyMDNS/message/DnsName.h
        ${SOURCE_ROOT}/TinyMDNS/message/DnsQuestion.h
        ${SOURCE_ROOT}/TinyMDNS/message/DnsRecord.h
        ${SOURCE_ROOT}/TinyMDNS/message/DnsMessage.h
        )

SET(Mdns_Source
        ${SOURCE_ROOT}/TinyMDNS/ServiceInfo.c
        ${SOURCE_ROOT}/TinyMDNS/MdnsHandler.c
        ${SOURCE_ROOT}/TinyMDNS/MdnsHandlerContext.c
        ${SOURCE_ROOT}/TinyMDNS/ServiceObserver.c
        ${SOURCE_ROOT}/TinyMDNS/codec/DnsMessageCodec.c
        ${SOURCE_ROOT}/TinyMDNS/message/DnsTypedef.c
        ${SOURCE_ROOT}/TinyMDNS/message/DnsName.c
        ${SOURCE_ROOT}/TinyMDNS/message/DnsQuestion.c
        ${SOURCE_ROOT}/TinyMDNS/message/DnsRecord.c
        ${SOURCE_ROOT}/TinyMDNS/message/DnsMessage.c
        )

SET(SRC
        ${Mdns_Header}
        ${Mdns_Source}
        )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(tinymdns_static STATIC ${SRC})
SET_TARGET_PROPERTIES(tinymdns_static PROPERTIES OUTPUT_NAME "tinymdns_static")
SET_TARGET_PROPERTIES(tinymdns_static PROPERTIES LINKER_LANGUAGE C)

ADD_LIBRARY(tinymdns SHARED ${SRC})
SET_TARGET_PROPERTIES(tinymdns PROPERTIES OUTPUT_NAME "tinymdns")
SET_TARGET_PROPERTIES(tinymdns PROPERTIES LINKER_LANGUAGE C)
TARGET_LINK_LIBRARIES(tinymdns ${DEPENDENCE_LIB})
