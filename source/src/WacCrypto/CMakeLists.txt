#-----------------------------------------------------------------------------
#
# WacCrypto
#
#-----------------------------------------------------------------------------

#-----------------------
# Curve25519
#-----------------------
SET(Curve25519_Header
        Curve25519/curve25519-donna.h
        )

SET(Curve25519_Source
        Curve25519/curve25519-donna.c
        )

SOURCE_GROUP(Curve25519\\headers        FILES     ${Curve25519_Header})
SOURCE_GROUP(Curve25519\\Source         FILES     ${Curve25519_Source})

#-----------------------
# AES
#-----------------------
SET(AES_Header
        GladmanAES/aes_via_ace.h
        GladmanAES/aes.h
        GladmanAES/aestab.h
        GladmanAES/aesopt.h
        GladmanAES/brg_endian.h
        GladmanAES/brg_types.h
        GladmanAES/gcm.h
        GladmanAES/gf_mul_lo.h
        GladmanAES/gf128mul.h
        GladmanAES/mode_hdr.h
        )

SET(AES_Source
        GladmanAES/aes_modes.c
        GladmanAES/aescrypt.c
        GladmanAES/aeskey.c
        GladmanAES/aestab.c
        GladmanAES/gcm.c
        GladmanAES/gf128mul.c
        )

SOURCE_GROUP(AES\\headers        FILES     ${AES_Header})
SOURCE_GROUP(AES\\Source         FILES     ${AES_Source})

#----------------------------------------------------------------------------
# source
#----------------------------------------------------------------------------
SET(SRC
        ${Curve25519_Header}
        ${Curve25519_Source}
        ${AES_Header}
        ${AES_Source}
    )

#----------------------------------------------------------------------------
# static library
#----------------------------------------------------------------------------
ADD_LIBRARY(wac_crypto_static STATIC ${SRC})
SET_TARGET_PROPERTIES(wac_crypto_static PROPERTIES OUTPUT_NAME "wac_crypto_static")
SET_TARGET_PROPERTIES(wac_crypto_static PROPERTIES LINKER_LANGUAGE C)
