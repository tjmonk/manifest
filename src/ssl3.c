/*==============================================================================
MIT License

Copyright (c) 2024 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup ssl3 SSL3 Helpers
 * @brief SSL3 Helper functions
 * @{
 */

/*============================================================================*/
/*!
@file ssl3.c

    SSL3.x Helper functions

    CalcSHA256
*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <openssl/evp.h>

/*==============================================================================
        Private definitions
==============================================================================*/

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*==============================================================================
        Private function declarations
==============================================================================*/

/*==============================================================================
        Function definitions
==============================================================================*/

/*============================================================================*/
/*  CalcSHA256                                                                */
/*!
    OpenSSL3.x SHA256 calculation on an open file

    The CalcSHA256 function calculates a SHA256 digest for an open file
    using OpenSSL 3.x functions.

    @param[in]
        fp
            pointer to an open file stream

    @param[in]
        out
            pointer to a buffer to store the ASCII SHA256 value

    @param[in]
        outlen
            length of the output buffer.

    @retval EOK SHA256 calculation ok
    @retval EINVAL invalid arguments
    @retval ENOMEM memory allocation failure

==============================================================================*/
int CalcSHA256( FILE *fp, char *out, size_t outlen )
{
    EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
    unsigned char mdVal[EVP_MAX_MD_SIZE];
    unsigned int mdLen;
    int result = EINVAL;
    int min_len = EVP_MAX_MD_SIZE + 1;
    const int bufSize = 32768;
    unsigned char *buffer;
    int bytesRead = 0;
    int i;

    if ( ( fp != NULL ) &&
         ( out != NULL ) &&
         ( outlen >= min_len ) )
    {
        /* allocate a working buffer */
        buffer = malloc(bufSize);
        if ( buffer != NULL )
        {
            EVP_DigestInit_ex( mdCtx, EVP_sha256(), NULL );

            /* read the buffer one chunk at a time */
            while( ( bytesRead = fread( buffer, 1, bufSize, fp ) ) )
            {
                /* process more data into the digest */
                EVP_DigestUpdate( mdCtx, buffer, bytesRead );
            }

            EVP_DigestFinal_ex( mdCtx, mdVal, &mdLen );
            if ( mdLen <= 32 )
            {
                /* convert the digest into a printable output */
                for( i = 0 ; i < mdLen ; i++ )
                {
                    sprintf( out + (i * 2), "%02x", mdVal[i] );
                }

                result = 0;
            }

            free( buffer );
        }
    }

    EVP_MD_CTX_free(mdCtx);

    return result;
}

/*! @}
 * end of ssl3 group */
