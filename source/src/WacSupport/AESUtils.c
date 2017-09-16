/*
    File:    AESUtils.c
    Package: WACServer
    Version: WAC_POSIX_Server_1.22
    
    Disclaimer: IMPORTANT: This Apple software is supplied to you, by Apple Inc. ("Apple"), in your
    capacity as a current, and in good standing, Licensee in the MFi Licensing Program. Use of this
    Apple software is governed by and subject to the terms and conditions of your MFi License,
    including, but not limited to, the restrictions specified in the provision entitled ”Public
    Software”, and is further subject to your agreement to the following additional terms, and your
    agreement that the use, installation, modification or redistribution of this Apple software
    constitutes acceptance of these additional terms. If you do not agree with these additional terms,
    please do not use, install, modify or redistribute this Apple software.
    
    Subject to all of these terms and in consideration of your agreement to abide by them, Apple grants
    you, for as long as you are a current and in good-standing MFi Licensee, a personal, non-exclusive
    license, under Apple's copyrights in this original Apple software (the "Apple Software"), to use,
    reproduce, and modify the Apple Software in source form, and to use, reproduce, modify, and
    redistribute the Apple Software, with or without modifications, in binary form. While you may not
    redistribute the Apple Software in source form, should you redistribute the Apple Software in binary
    form, you must retain this notice and the following text and disclaimers in all such redistributions
    of the Apple Software. Neither the name, trademarks, service marks, or logos of Apple Inc. may be
    used to endorse or promote products derived from the Apple Software without specific prior written
    permission from Apple. Except as expressly stated in this notice, no other rights or licenses,
    express or implied, are granted by Apple herein, including but not limited to any patent rights that
    may be infringed by your derivative works or by other works in which the Apple Software may be
    incorporated.
    
    Unless you explicitly state otherwise, if you provide any ideas, suggestions, recommendations, bug
    fixes or enhancements to Apple in connection with this software (“Feedback”), you hereby grant to
    Apple a non-exclusive, fully paid-up, perpetual, irrevocable, worldwide license to make, use,
    reproduce, incorporate, modify, display, perform, sell, make or have made derivative works of,
    distribute (directly or indirectly) and sublicense, such Feedback in connection with Apple products
    and services. Providing this Feedback is voluntary, but if you do provide Feedback to Apple, you
    acknowledge and agree that Apple may exercise the license granted above without the payment of
    royalties or further consideration to Participant.
    
    The Apple Software is provided by Apple on an "AS IS" basis. APPLE MAKES NO WARRANTIES, EXPRESS OR
    IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR
    IN COMBINATION WITH YOUR PRODUCTS.
    
    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION
    AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
    (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
    
    Copyright (C) 2013 Apple Inc. All Rights Reserved.
*/

#include "AESUtils.h"

//===========================================================================================================================
//  AES_CTR_Init
//===========================================================================================================================

OSStatus
AES_CTR_Init(
        AES_CTR_Context *inContext,
        const uint8_t inKey[kAES_CTR_Size],
        const uint8_t inNonce[kAES_CTR_Size])
{
    aes_init();
    aes_encrypt_key128(inKey, &inContext->ctx);

    memcpy(inContext->ctr, inNonce, kAES_CTR_Size);
    inContext->used = 0;
    inContext->legacy = false;
    return (kNoErr);
}

//===========================================================================================================================
//  AES_CTR_Increment
//===========================================================================================================================

static inline void AES_CTR_Increment(uint8_t *inCounter)
{
    int i;

    // Note: counter is always big endian so this adds from right to left.

    for (i = kAES_CTR_Size - 1; i >= 0; --i)
    {
        if (++(inCounter[i]) != 0)
        {
            break;
        }
    }
}

//===========================================================================================================================
//  AES_CTR_Update
//===========================================================================================================================

OSStatus AES_CTR_Update(AES_CTR_Context *inContext, const void *inSrc, size_t inLen, void *inDst)
{
    OSStatus err;
    const uint8_t *src;
    uint8_t *dst;
    uint8_t *buf;
    size_t used;
    size_t i;

    // inSrc and inDst may be the same, but otherwise, the buffers must not overlap.

    src = (const uint8_t *) inSrc;
    dst = (uint8_t *) inDst;

    // If there's any buffered key material from a previous block then use that first.

    buf = inContext->buf;
    used = inContext->used;
    while ((inLen > 0) && (used != 0))
    {
        *dst++ = *src++ ^ buf[used++];
        used %= kAES_CTR_Size;
        inLen -= 1;
    }
    inContext->used = used;

    // Process whole blocks.

    while (inLen >= kAES_CTR_Size)
    {
        aes_ecb_encrypt(inContext->ctr, buf, kAES_CTR_Size, &inContext->ctx);

        AES_CTR_Increment(inContext->ctr);

        for (i = 0; i < kAES_CTR_Size; ++i)
        {
            dst[i] = src[i] ^ buf[i];
        }
        src += kAES_CTR_Size;
        dst += kAES_CTR_Size;
        inLen -= kAES_CTR_Size;
    }

    // Process any trailing sub-block bytes. Extra key material is buffered for next time.

    if (inLen > 0)
    {
        aes_ecb_encrypt(inContext->ctr, buf, kAES_CTR_Size, &inContext->ctx);

        AES_CTR_Increment(inContext->ctr);

        for (i = 0; i < inLen; ++i)
        {
            *dst++ = *src++ ^ buf[used++];
        }

        // For legacy mode, always leave the used amount as 0 so we always increment the counter each time.

        if (!inContext->legacy)
        {
            inContext->used = used;
        }
    }
    err = kNoErr;

    return (err);
}

//===========================================================================================================================
//  AES_CTR_Final
//===========================================================================================================================

void AES_CTR_Final(AES_CTR_Context *inContext)
{
    memset(inContext, 0, sizeof(*inContext)); // Clear sensitive data.
}

//===========================================================================================================================
//  AES_CBCFrame_Init
//===========================================================================================================================

OSStatus
AES_CBCFrame_Init(
        AES_CBCFrame_Context *inContext,
        const uint8_t inKey[kAES_CBCFrame_Size],
        const uint8_t inIV[kAES_CBCFrame_Size],
        Boolean inEncrypt)
{
    aes_init();
    if (inEncrypt)
    {
        aes_encrypt_key128(inKey, &inContext->ctx.encrypt);
    }
    else
    {
        aes_decrypt_key128(inKey, &inContext->ctx.decrypt);
    }
    inContext->encrypt = inEncrypt;

    memcpy(inContext->iv, inIV, kAES_CBCFrame_Size);
    return (kNoErr);
}

//===========================================================================================================================
//  AES_CBCFrame_Update
//===========================================================================================================================

OSStatus AES_CBCFrame_Update(AES_CBCFrame_Context *inContext, const void *inSrc, size_t inSrcLen, void *inDst)
{
    OSStatus err;
    const uint8_t *src;
    const uint8_t *end;
    uint8_t *dst;
    size_t len;

    src = (const uint8_t *) inSrc;
    end = src + inSrcLen;
    dst = (uint8_t *) inDst;

    // Process whole blocks.

    len = inSrcLen & ~((size_t) (kAES_CBCFrame_Size - 1));
    if (len > 0)
    {
        uint8_t iv[kAES_CBCFrame_Size];

        memcpy(iv, inContext->iv, kAES_CBCFrame_Size); // Use local copy so original IV is not changed.
        if (inContext->encrypt)
        {
            aes_cbc_encrypt(src, dst, (int) len, iv, &inContext->ctx.encrypt);
        }
        else
        {
            aes_cbc_decrypt(src, dst, (int) len, iv, &inContext->ctx.decrypt);
        }

        src += len;
        dst += len;
    }

    // The remaining bytes are just copied unencrypted.

    while (src != end)
    {
        *dst++ = *src++;
    }
    err = kNoErr;

    return (err);
}

//===========================================================================================================================
//  AES_CBCFrame_Update2
//===========================================================================================================================

OSStatus
AES_CBCFrame_Update2(
        AES_CBCFrame_Context *inContext,
        const void *inSrc1,
        size_t inLen1,
        const void *inSrc2,
        size_t inLen2,
        void *inDst)
{
    const uint8_t *src1 = (const uint8_t *) inSrc1;
    const uint8_t *end1 = src1 + inLen1;
    const uint8_t *src2 = (const uint8_t *) inSrc2;
    const uint8_t *end2 = src2 + inLen2;
    uint8_t *dst = (uint8_t *) inDst;
    OSStatus err;
    size_t len;
    size_t i;

#if(!AES_UTILS_USE_COMMON_CRYPTO)
    uint8_t iv[kAES_CBCFrame_Size];
#endif

    memcpy(iv, inContext->iv, kAES_CBCFrame_Size); // Use local copy so original IV is not changed.

    // Process all whole blocks from buffer 1.

    len = inLen1 & ~((size_t) (kAES_CBCFrame_Size - 1));
    if (len > 0)
    {
        if (inContext->encrypt)
        {
            aes_cbc_encrypt(src1, dst, (int) len, iv, &inContext->ctx.encrypt);
        }
        else
        {
            aes_cbc_decrypt(src1, dst, (int) len, iv, &inContext->ctx.decrypt);
        }

        src1 += len;
        dst += len;
    }

    // If there are any partial block bytes in buffer 1 and enough bytes in buffer 2 to fill a 
    // block then combine them into a temporary buffer and encrypt it.

    if ((src1 != end1) && (((end1 - src1) + (end2 - src2)) >= kAES_CBCFrame_Size))
    {
        uint8_t buf[kAES_CBCFrame_Size];

        for (i = 0; src1 != end1; ++i)
        {
            buf[i] = *src1++;
        }

        for (; (i < kAES_CBCFrame_Size) && (src2 != end2); ++i)
        {
            buf[i] = *src2++;
        }

        if (inContext->encrypt)
        {
            aes_cbc_encrypt(buf, dst, (int) i, iv, &inContext->ctx.encrypt);
        }
        else
        {
            aes_cbc_decrypt(buf, dst, (int) i, iv, &inContext->ctx.decrypt);
        }

        dst += i;
    }

    // Process any remaining whole blocks in buffer 2.

    len = ((size_t) (end2 - src2)) & ~((size_t) (kAES_CBCFrame_Size - 1));
    if (len > 0)
    {
        if (inContext->encrypt)
        {
            aes_cbc_encrypt(src2, dst, (int) len, iv, &inContext->ctx.encrypt);
        }
        else
        {
            aes_cbc_decrypt(src2, dst, (int) len, iv, &inContext->ctx.decrypt);
        }

        src2 += len;
        dst += len;
    }

    // Any remaining bytes are just copied unencrypted.

    while (src1 != end1)
    {
        *dst++ = *src1++;
    }
    while (src2 != end2)
    {
        *dst++ = *src2++;
    }
    err = kNoErr;

    return (err);
}

//===========================================================================================================================
//  AES_CBCFrame_Final
//===========================================================================================================================

void AES_CBCFrame_Final(AES_CBCFrame_Context *inContext)
{
    memset(inContext, 0, sizeof(*inContext)); // Clear sensitive data.
}

//===========================================================================================================================
//  AES_cbc_encrypt
//===========================================================================================================================

//===========================================================================================================================
//  AES_ECB_Init
//===========================================================================================================================

OSStatus AES_ECB_Init(AES_ECB_Context *inContext, uint32_t inMode, const uint8_t inKey[kAES_ECB_Size])
{
    aes_init();

    if (inMode == kAES_ECB_Mode_Encrypt)
    {
        aes_encrypt_key128(inKey, &inContext->ctx.encrypt);
    }
    else
    {
        aes_decrypt_key128(inKey, &inContext->ctx.decrypt);
    }

    inContext->encrypt = inMode;

    return (kNoErr);
}

//===========================================================================================================================
//  AES_ECB_Update
//===========================================================================================================================

OSStatus AES_ECB_Update(AES_ECB_Context *inContext, const void *inSrc, size_t inLen, void *inDst)
{
    OSStatus err;
    const uint8_t *src;
    uint8_t *dst;
    size_t n;

    // inSrc and inDst may be the same, but otherwise, the buffers must not overlap.

    src = (const uint8_t *) inSrc;
    dst = (uint8_t *) inDst;
    for (n = inLen / kAES_ECB_Size; n > 0; --n)
    {
        if (inContext->encrypt)
        {
            aes_ecb_encrypt(src, dst, kAES_ECB_Size, &inContext->ctx.encrypt);
        }
        else
        {
            aes_ecb_decrypt(src, dst, kAES_ECB_Size, &inContext->ctx.decrypt);
        }

        src += kAES_ECB_Size;
        dst += kAES_ECB_Size;
    }
    err = kNoErr;

    return (err);
}

//===========================================================================================================================
//  AES_ECB_Final
//===========================================================================================================================

void AES_ECB_Final(AES_ECB_Context *inContext)
{
    memset(inContext, 0, sizeof(*inContext)); // Clear sensitive data.
}

#if(AES_UTILS_HAS_GCM)

//===========================================================================================================================
//  AES_GCM_Init
//===========================================================================================================================

OSStatus
AES_GCM_Init(
        AES_GCM_Context *inContext,
        const uint8_t inKey[kAES_CGM_Size],
        const uint8_t inNonce[kAES_CGM_Size])
{
    OSStatus err;

    do
    {
        err = gcm_init_and_key(inKey, kAES_CGM_Size, &inContext->ctx);
        if (err != kNoErr)
        {
            break;
        }

        if (inNonce)
        {
            memcpy(inContext->nonce, inNonce, kAES_CGM_Size);
        }

    } while (false);

    return (err);
}

//===========================================================================================================================
//  AES_GCM_Final
//===========================================================================================================================

void AES_GCM_Final(AES_GCM_Context *inContext)
{
    gcm_end(&inContext->ctx);
    memset(inContext, 0, sizeof(*inContext)); // Clear sensitive data.
}

//===========================================================================================================================
//  AES_GCM_InitMessage
//===========================================================================================================================
OSStatus AES_GCM_InitMessage(AES_GCM_Context *inContext, const uint8_t inNonce[kAES_CGM_Size])
{
    if (inNonce == kAES_CGM_Nonce_Auto)
    {
        AES_CTR_Increment(inContext->nonce);
        inNonce = inContext->nonce;
    }

    return gcm_init_message(inNonce, kAES_CGM_Size, &inContext->ctx);
}

//===========================================================================================================================
//  AES_GCM_FinalizeMessage
//===========================================================================================================================
OSStatus AES_GCM_FinalizeMessage(AES_GCM_Context *inContext, uint8_t outAuthTag[kAES_CGM_Size])
{
    return gcm_compute_tag(outAuthTag, kAES_CGM_Size, &inContext->ctx);
}

//===========================================================================================================================
//  AES_GCM_VerifyMessage
//===========================================================================================================================
OSStatus AES_GCM_VerifyMessage(AES_GCM_Context *inContext, const uint8_t inAuthTag[kAES_CGM_Size])
{
    OSStatus err = kNoErr;
    uint8_t authTag[kAES_CGM_Size];

    do
    {
        err = gcm_compute_tag(authTag, kAES_CGM_Size, &inContext->ctx);
        if (err != kNoErr)
        {
            break;
        }

        if (memcmp_constant_time(authTag, inAuthTag, kAES_CGM_Size) != 0)
        {
            err = kAuthenticationErr;
            break;
        }
    } while (false);

    return (err);
}

//===========================================================================================================================
//  AES_GCM_AddAAD
//===========================================================================================================================
OSStatus AES_GCM_AddAAD(AES_GCM_Context *inContext, const void *inPtr, size_t inLen)
{
    return gcm_auth_header(inPtr, inLen, &inContext->ctx);
}

//===========================================================================================================================
//  AES_GCM_Encrypt
//===========================================================================================================================
OSStatus AES_GCM_Encrypt(AES_GCM_Context *inContext, const void *inSrc, size_t inLen, void *inDst)
{
    return gcm_encrypt(inDst, inSrc, inLen, &inContext->ctx);
}

//===========================================================================================================================
//  AES_GCM_Decrypt
//===========================================================================================================================
OSStatus AES_GCM_Decrypt(AES_GCM_Context *inContext, const void *inSrc, size_t inLen, void *inDst)
{
    return gcm_decrypt(inDst, inSrc, inLen, &inContext->ctx);
}

#endif
