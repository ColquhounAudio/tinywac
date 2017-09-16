CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(TinyWAC C)

SET(PROJ_NAME "TinyWAC")

#---------------------------------------------------------------------------------------
#
# include dir
#
#---------------------------------------------------------------------------------------
SET(SOURCE_ROOT ${PROJECT_SOURCE_DIR}/src)
SET(TINY_ROOT ${PROJECT_SOURCE_DIR}/../../tiny)

INCLUDE_DIRECTORIES(${SOURCE_ROOT}/WacCrypto)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/WacPortable)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/WacServer)
INCLUDE_DIRECTORIES(${SOURCE_ROOT}/WacSupport)

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
ADD_SUBDIRECTORY(src)
