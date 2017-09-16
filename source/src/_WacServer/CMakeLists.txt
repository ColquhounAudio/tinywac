#-----------------------------------------------------------------------------
#
# WacServer
#
#-----------------------------------------------------------------------------

SET(WacServer_Header
        Common.h
        WACBonjour.h
        WACLogging.h
        WACServerAPI.h
        WACServerVersion.h
        WACTLV.h
        )

SET(WacServer_Source
        WACBonjour.c
        WACServer.c
        )

SOURCE_GROUP(WacServer\\headers        FILES     ${WacServer_Header})
SOURCE_GROUP(WacServer\\Source         FILES     ${WacServer_Source})

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${WacServer_Header}
        ${WacServer_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(wac_server_static STATIC ${SRC})
SET_TARGET_PROPERTIES(wac_server_static PROPERTIES OUTPUT_NAME "wac_server_static")
SET_TARGET_PROPERTIES(wac_server_static PROPERTIES LINKER_LANGUAGE C)
