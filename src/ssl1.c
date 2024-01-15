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
 * @defgroup ssl1 SSL1 Helpers
 * @brief SSL1 Helper functions
 * @{
 */

/*============================================================================*/
/*!
@file ssl1.c

    SSL1.x Helper functions

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
#include <openssl/sha.h>

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
    OpenSSL1.x SHA256 calculation on an open file

    The CalcSHA256 function calculates a SHA256 digest for an open file
    using OpenSSL 1.x functions.

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
    int result = EINVAL;
    int min_len = ( SHA256_DIGEST_LENGTH * 2 ) + 1;
    SHA256_CTX sha256;
    const int bufSize = 32768;
    unsigned char *buffer = NULL;
    int bytesRead = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i;

    if ( ( fp != NULL ) &&
         ( out != NULL ) &&
         ( outlen >= min_len ) )
    {
        /* allocate a working buffer */
        buffer = malloc(bufSize);
        if ( buffer != NULL )
        {
            /* start SHA256 digest */
            SHA256_Init(&sha256);
            while( ( bytesRead = fread(buffer, 1, bufSize, fp) ) )
            {
                /* process more data into the digest */
                SHA256_Update( &sha256, buffer, bytesRead );
            }

            /* complete the digest */
            SHA256_Final( hash, &sha256 );

            /* convert the digest into a printable output */
            for( i = 0 ; i < SHA256_DIGEST_LENGTH ; i++ )
            {
                sprintf( out + (i * 2), "%02x", hash[i] );
            }

            /* free the buffer */
            free( buffer );

            /* indicate success */
            result = 0;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

/*! @}
 * end of ssl1 group */
