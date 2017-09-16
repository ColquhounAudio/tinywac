#-----------------------------------------------------------------------------
#
# WacPortable
#
#-----------------------------------------------------------------------------

SET(ESP8266_Header
        esp8266/PlatformApplyConfiguration.h
        esp8266/PlatformBonjour.h
        esp8266/PlatformLogging.h
        esp8266/PlatformMFiAuth.h
        esp8266/PlatformRandomNumber.h
        esp8266/PlatformSoftwareAccessPoint.h
        )

SET(ESP8266_Source
        esp8266/PlatformApplyConfiguration.c
        esp8266/PlatformBonjour.c
        esp8266/PlatformLogging.c
        esp8266/PlatformMFiAuth.c
        esp8266/PlatformRandomNumber.c
        esp8266/PlatformSoftwareAccessPoint.c
        )

SOURCE_GROUP(ESP8266\\headers        FILES     ${ESP8266_Header})
SOURCE_GROUP(ESP8266\\Source         FILES     ${ESP8266_Source})

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${ESP8266_Header}
        ${ESP8266_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(wac_portable_static STATIC ${SRC})
SET_TARGET_PROPERTIES(wac_portable_static PROPERTIES OUTPUT_NAME "wac_portable_static")
SET_TARGET_PROPERTIES(wac_portable_static PROPERTIES LINKER_LANGUAGE C)
