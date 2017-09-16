#-----------------------------------------------------------------------------
#
# WacSupport
#
#-----------------------------------------------------------------------------

SET(WacSupport_Header
        AESUtils.h
        AppleDeviceIE.h
        MFiSAPServer.h
        SecurityUtils.h
        SHAUtils.h
        StringUtils.h
        TimeUtils.h
        TLVUtils.h
        URLUtils.h
        )

SET(WacSupport_Source
        AESUtils.c
        AppleDeviceIE.c
        MFiSAPServer.c
        SecurityUtils.c
        SHAUtils.c
        StringUtils.c
        TimeUtils.c
        TLVUtils.c
        URLUtils.c
        )

SOURCE_GROUP(WacSupport\\headers        FILES     ${WacSupport_Header})
SOURCE_GROUP(WacSupport\\Source         FILES     ${WacSupport_Source})

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${WacSupport_Header}
        ${WacSupport_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(wac_support_static STATIC ${SRC})
SET_TARGET_PROPERTIES(wac_support_static PROPERTIES OUTPUT_NAME "wac_support_static")
SET_TARGET_PROPERTIES(wac_support_static PROPERTIES LINKER_LANGUAGE C)
