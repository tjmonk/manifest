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
 * @defgroup manifest Manifest Generator
 * @brief Construct a dynamic file manifest
 * @{
 */

/*============================================================================*/
/*!
@file manifest.c

    Manifest Generator

    The manifest service generates a file manifest object which contains
    a list of files and their associated SHA256 digest.

    The manifest service continues to monitor the manifest files for changes
    and will update the file SHA if the file changes.

    The manifest is available via a rendered sysvar.

    The manifest configuration is specified via a command line argument
    which references a configuration file which looks like the following:

    {
        "manifest" : "/manifest",
        "sources" : [
            "/usr/local/include"
        ]
    }

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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <time.h>
#include <dirent.h>
#include <tjson/json.h>
#include <varserver/vartemplate.h>
#include <varserver/varserver.h>
#include <varserver/varcache.h>
#include <varserver/varquery.h>
#include <varserver/varfp.h>
//#include <openssl/sha.h>
#include <openssl/evp.h>
#include "ssl.h"

/*==============================================================================
        Private definitions
==============================================================================*/

typedef struct _fileRef
{
    /*! file name specifier */
    char *name;

    /*! calculated SHA256 */
    char sha[65];

    /*! pointer to the next FileRef object */
    struct _fileRef *pNext;
} FileRef;

/*! Manifest state object */
typedef struct _manifestState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose flag */
    bool verbose;

    /*! name of the configuration file */
    char *pConfigFile;

    /*! the number of files this service is managing */
    uint32_t numMsgs;

    /*! manifest name */
    char *name;

    /*! list of FileRef objects which make up the manifest */
    FileRef *pManifest;

} ManifestState;

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! Variable Message Manager State */
static ManifestState state;

/*! handle to the variable server */
VARSERVER_HANDLE hVarServer = NULL;

/*==============================================================================
        Private function declarations
==============================================================================*/

int main(int argc, char **argv);
static int ProcessOptions( int argC, char *argV[], ManifestState *pState );
static void usage( char *cmdname );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );
static void SetupTerminationHandler( void );
static int ProcessSources( ManifestState *pState, JArray *pSources );
static int ProcessConfigFile( ManifestState *pState, char *filename );

static int AddSource( ManifestState *pState, char *name );
static int AddDir( ManifestState *pState, char *name );
static int AddFile( ManifestState *pState, char *name );

static int CalcManifest( FileRef *pFileRef );

static int MakeFileName( char *dirname, char *filename, char *out, size_t len );

static int DumpManifest( ManifestState *pState, int fd );

/*==============================================================================
        Private function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the Manifest Generator application

    The main function starts the Manifest Generator application

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @retval 0 - no error
    @retval 1 - an error occurred

==============================================================================*/
int main(int argc, char **argv)
{
    int result = EINVAL;

    OpenSSL_add_all_digests();

    /* clear the variable message state object */
    memset( &state, 0, sizeof( state ) );

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* set up the abnormal termination handler */
    SetupTerminationHandler();

    /* open a handle to the variable server */
    hVarServer = VARSERVER_Open();
    if( hVarServer != NULL )
    {
        state.hVarServer = hVarServer;

        if ( state.pConfigFile != NULL )
        {
            /* Process the configuration file */
            result = ProcessConfigFile( &state, state.pConfigFile );
            if ( result == EOK )
            {
                DumpManifest( &state, STDOUT_FILENO );

                //RunManifestGenerator( &state );
            }
        }

        /* close the handle to the variable server */
        VARSERVER_Close( hVarServer );
    }

    return ( result == EOK ) ? 0 : 1;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message
    to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] [-f config file] [-d config dir]\n"
                " [-h] : display this help\n"
                " [-v] : verbose output\n"
                " [-f] : specify the manifest configuration file\n",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the ExecVarState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the variable message generator state object

    @return 0

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], ManifestState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "hvf:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'v':
                    pState->verbose = true;
                    break;

                case 'h':
                    usage( argV[0] );
                    break;

                case 'f':
                    pState->pConfigFile = strdup(optarg);
                    break;

                default:
                    break;
            }
        }
    }

    return 0;
}

/*============================================================================*/
/*  ProcessConfigFile                                                         */
/*!
    Process the specified configuration file

    The ProcessConfigFile function processes a configuration file
    consisting of lines of directives and variable assignments.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        filename
            pointer to the name of the file to load

    @retval EINVAL invalid arguments
    @retval EOK file processed ok
    @retval other error as returned by ProcessConfigData

==============================================================================*/
static int ProcessConfigFile( ManifestState *pState, char *filename )
{
    int result = EINVAL;
    char *pFileName = NULL;
    JNode *config;
    JNode *node;
    JArray *pSources;

    int n;
    int i;

    if ( filename != NULL )
    {
        pFileName = strdup( filename );
    }

    if ( ( pState != NULL ) &&
         ( pFileName != NULL ) )
    {
        if ( pState->verbose == true )
        {
            printf("ProcessConfigFile: %s\n", pFileName );
        }

        /* parse the JSON config file */
        config = JSON_Process( pFileName );
        if ( config != NULL )
        {
            /* get the manifest name */
            pState->name = JSON_GetStr(config, "manifest");
            if ( pState->name != NULL )
            {
                printf("manifest: %s\n", pState->name );

                /* get the sources list */
                node = JSON_Find( config, "sources" );
                if ( node->type == JSON_ARRAY )
                {
                    /* process the sources list */
                    pSources = (JArray *)node;
                    result = ProcessSources( pState, pSources );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessSources                                                            */
/*!
    Process the "sources" array in the manifest configuration file

    The ProcessSources function processes an array of source file/directory
    strings from the configuration file.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        pSources
            pointer to a JSON Array containing source files and directories

    @retval EINVAL invalid arguments
    @retval EOK sources processed ok
    @retval other error as returned by ProcessConfigData

==============================================================================*/
static int ProcessSources( ManifestState *pState, JArray *pSources )
{
    int result = EINVAL;
    JNode *pNode;
    JVar *pVar;
    int n;
    int i;
    int rc;
    int count = 0;

    if ( ( pState != NULL ) &&
         ( pSources != NULL ) )
    {
        result = EOK;

        /* get the length of the sources array */
        n = JSON_GetArraySize( pSources );
        if ( n > 0 )
        {
            /* iterate through the source list */
            for ( i = 0; i < n ; i++ )
            {
                /* get the array item at the specified index */
                pNode = JSON_Index( pSources, i );
                if ( pNode->type == JSON_VAR )
                {
                    pVar = (JVar *)pNode;
                    if ( pVar->var.type == JVARTYPE_STR )
                    {
                        /* add the source to the manifest */
                        rc = AddSource( pState, pVar->var.val.str );
                        if ( rc == EOK )
                        {
                            /* count the number of sources added */
                            count++;
                        }
                        else
                        {
                            result = rc;
                        }
                    }
                    else
                    {
                        printf("Invalid source specification\n");
                        result = ENOTSUP;
                    }
                }
                else
                {
                    printf("Invalid source index\n");
                    result = ENOTSUP;
                }
            }
        }

        if ( count == 0 )
        {
            /* no sources listed */
            printf( "No sources in manifest configuration: %s\n",
                    pState->pConfigFile );
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  AddSource                                                                 */
/*!
    Add a source reference to the manifest

    The AddSource function adds a source reference to the manfest.
    The source could refer to a file or a directory.  In the case of a
    directory, all of the files in the directory will be added but any
    directory will be ignored.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        name
            name of the source to add

    @retval EINVAL invalid arguments
    @retval EOK sources processed ok
    @retval ENOTSUP unsupported file type
    @retval other error from stat

==============================================================================*/
static int AddSource( ManifestState *pState, char *name )
{
    struct stat sb;
    int result = EINVAL;
    int rc;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        /* get information about the file or directory */
        rc = stat( name, &sb );
        if ( rc == 0 )
        {
            /* check the stat information */
            switch( sb.st_mode & S_IFMT )
            {
                case S_IFDIR:
                    result = AddDir( pState, name );
                    break;

                case S_IFREG:
                    result = AddFile( pState, name );
                    break;

                default:
                    printf("Unsupported filetype: %s\n", name );
                    result = ENOTSUP;
                    break;
            }
        }
        else
        {
            result = errno;
            printf("Failed to stat: %s\n", name );
        }
    }

    return result;

}

/*============================================================================*/
/*  MakeFileName                                                              */
/*!
    Construct a file name from a directory name and file name

    The MakeFileName function constructs a file name by concatenating
    a directory name and a file name into the output buffer.
    If the directory name does not contain a trailing slash, one
    will be added.

    @param[in]
        dirname
            name of the directory

    @param[in]
        filename
            name of the file

    @param[in,out]
        out
            pointer to the output buffer

    @param[in]
        len
            length of the output buffer

    @retval EINVAL invalid arguments
    @retval E2BIG not enough space in the output buffer
    @retval EOK sources processed ok

==============================================================================*/
static int MakeFileName( char *dirname, char *filename, char *out, size_t len )
{
    int result = EINVAL;
    size_t n;
    size_t left = len;
    size_t offset = 0;

    if ( ( dirname != NULL ) &&
         ( filename != NULL ) &&
         ( out != NULL ) &&
         ( len > 0 ) )
    {
        /* set default error */
        result = E2BIG;

        /* calculate the length of the directory name */
        n = strlen( dirname );
        if ( n < left )
        {
            /* copy the directory name */
            strcpy( out, dirname );
            left -= n;
            offset += n;

            if ( out[offset-1] != '/' )
            {
                if ( left > 1 )
                {
                    /* append a trailing slash */
                    out[offset++] = '/';
                    left--;
                }
            }

            /* get the length of the file name */
            n = strlen( filename );
            if ( n < left )
            {
                /* append the file name */
                strcpy( &out[offset], filename );
                offset += n;
                left -= n;

                /* NUL terminate */
                out[offset] = 0;

                /* success */
                result = EOK;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  AddDir                                                                    */
/*!
    Add a directory to the manifest

    The AddDir function iterates through the specified directory and adds
    each file found to the manifest.

    @param[in]
        pState
            pointer to the Manifest State object

    @param[in]
        name
            name of the directory to add

    @retval EINVAL invalid arguments
    @retval EOK directory added ok

==============================================================================*/
static int AddDir( ManifestState *pState, char *name )
{
    int result = EINVAL;
    struct dirent *entry;
    DIR *pDir;
    struct stat sb;
    char buf[BUFSIZ];
    char *pFile;
    int rc;
    int errcount = 0;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        pDir = opendir( name );
        if( pDir != NULL )
        {
            while( entry = readdir( pDir ) )
            {
                /* construct the file name from the directory name
                   and the file name */
                rc = MakeFileName( name, entry->d_name, buf, sizeof( buf ) );
                if ( rc == EOK )
                {
                    /* stat the file name */
                    rc = stat( buf, &sb );
                    if ( ( rc == 0 ) &&
                         ( ( sb.st_mode & S_IFMT ) == S_IFREG ) )
                    {
                        /* duplicate the filename string */
                        pFile = strdup( buf );
                        if ( pFile != NULL )
                        {
                            /* add the file to the manifest */
                            result = AddFile( pState, buf );
                            if ( result != EOK )
                            {
                                errcount++;
                            }
                        }
                        else
                        {
                            /* cannot allocate memory */
                            printf("Cannot allocate memory for %s\n", buf );
                            errcount++;
                        }
                    }
                }
                else
                {
                    errcount++;
                }
            }

            closedir( pDir );
        }
    }

    if ( errcount == 0 )
    {
        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  AddFile                                                                   */
/*!
    Add a file to the manifest

    The AddFile function adds the specified file to the manifest and
    calculates its SHA256

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        name
            name of the file to generate a digest for

    @retval EINVAL invalid arguments
    @retval EOK sources processed ok
    @retval ENOMEM memory allocation failure
    @retval EBADF cannot open file

==============================================================================*/
static int AddFile( ManifestState *pState, char *name )
{
    FileRef *pFileRef;
    int result = EINVAL;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        /* allocate memory for the manifest file reference */
        pFileRef = calloc( 1, sizeof( FileRef ) );
        if ( pFileRef != NULL )
        {
            /* set the file name */
            pFileRef->name = name;

            /* perform digest */
            result = CalcManifest( pFileRef );
            if ( result == EOK )
            {
                /* add the manifest entry file reference to the manifest list */
                pFileRef->pNext = pState->pManifest;
                pState->pManifest = pFileRef;
            }
            else
            {
                free( pFileRef );
                printf("Error calculating digest for %s\n", name );
            }
        }
        else
        {
            /* failed to allocate memory for the file reference */
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  CalcManifest                                                              */
/*!
    Calculate the manifest for the specified file reference

    The CalcManifest function opens the file referenced in the file reference
    object and creates the SHA256 digest of the file.

    @param[in]
        pFileRef
            pointer to the File Reference to calculate

    @retval EINVAL invalid arguments
    @retval EOK digest processed ok
    @retval ENOMEM memory allocation failure
    @retval EBADF cannot open file

==============================================================================*/
static int CalcManifest( FileRef *pFileRef )
{
    int result = EINVAL;
    FILE *fp;

    if ( ( pFileRef != NULL ) &&
         ( pFileRef->name != NULL ) )
    {
        fp = fopen( pFileRef->name, "rb");
        if ( fp != NULL )
        {
            /* calculate the SHA256 */
            result = CalcSHA256( fp, pFileRef->sha, sizeof( pFileRef->sha ) );

            /* close the source file */
            fclose( fp );
        }
        else
        {
            result = EBADF;
        }
    }

    return result;
}

/*============================================================================*/
/*  DumpManifest                                                              */
/*!
    Dump the manifest to the output file descriptor

    The DumpManifest function dumps the manifest to the output file descriptor

    @param[in]
        pState
            pointer to the Manifest state object

    @param[in]
        fd
            output file descriptor

    @retval EINVAL invalid arguments
    @retval EOK digest processed ok
    @retval ENOMEM memory allocation failure
    @retval EBADF cannot open file

==============================================================================*/
static int DumpManifest( ManifestState *pState, int fd )
{
    int result = EINVAL;
    FileRef *pFileRef;
    int count = 0;

    /* output the start of the JSON object */
    write( fd, "{", 1 );

    if ( pState != NULL )
    {
        result = EOK;

        /* point to the first manifest entry */
        pFileRef = pState->pManifest;
        while ( pFileRef != NULL )
        {
            if ( count > 0 )
            {
                /* prepend a comma */
                write( fd, ",", 1 );
            }

            /* generate the filename and SHA */
            dprintf( fd, "\"%s\":\"%s\"", pFileRef->name, pFileRef->sha );
            count++;

            /* get the next file reference */
            pFileRef = pFileRef->pNext;
        }
    }

    /* output the end of the JSON object */
    write( fd, "}", 1 );

    return result;
}

/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );
    sigaction( SIGINT, &sigact, NULL );

}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server and cleans up any open
    resources.

    @param[in]
        signum
            The signal which caused the abnormal termination (unused)

    @param[in]
        info
            pointer to a siginfo_t object (unused)

    @param[in]
        ptr
            signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

    printf("Abnormal termination of the manifest generator \n" );

    if ( state.hVarServer != NULL )
    {
        VARSERVER_Close( state.hVarServer );
    }

    exit( 1 );
}

/*! @}
 * end of manifest group */
