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
#include <openssl/evp.h>
#include <sys/inotify.h>
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

    /*! file watch id */
    int id;

    /*! pointer to the next FileRef object */
    struct _fileRef *pNext;
} FileRef;

/*! change log entry */
typedef struct _changeLogEntry
{
    /*! time of change */
    time_t t;

    /*! inotify watch id */
    int id;
} ChangeLogEntry;

/*! Manifest state object */
typedef struct _manifestState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose flag */
    bool verbose;

    /*! notify file descriptor */
    int notifyfd;

    /*! name of the configuration file */
    char *pConfigFile;

    /*! the number of files this service is managing */
    uint32_t numMsgs;

    /*! manifest name */
    char *name;

    /*! render variable */
    char *renderVarName;

    /*! handle to the render variable */
    VAR_HANDLE hRenderVar;

    /*! name of the counter variable */
    char *countVarName;

    /*! handle to the counter variable */
    VAR_HANDLE hCountVar;

    /*! name of the change log variable */
    char *changeLogName;

    /*! handle to the change log render variable */
    VAR_HANDLE hChangeLog;

    /*! list of FileRef objects which make up the manifest */
    FileRef *pManifest;

    /*! count the number of times a monitored file has changed */
    size_t changeCount;

    /*! flag to keep the manifest generator service running */
    bool running;

    /*! maximum number of change log entries */
    size_t maxEntries;

    /*! number of entries in the circular buffer */
    size_t nEntries;

    /*! indicate start of the circular log */
    size_t in;

    /*! indicate end of the circular log */
    size_t out;

    /* pointer to the change log */
    ChangeLogEntry *pChangeLog;

} ManifestState;

/*! Var Definition object to define a message variable to be created */
typedef struct _varDef
{
    /* name of the variable */
    char *name;

    /* variable flags to be set */
    uint32_t flags;

    /*! notification type for the variable */
    NotificationType notifyType;

    /*! pointer to a location to store the variable handle once it is created */
    VAR_HANDLE *pVarHandle;
} VarDef;

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

static int SetupVars( ManifestState *pState );
VAR_HANDLE SetupVar( ManifestState *pState,
                     char *name,
                     uint32_t flags,
                     NotificationType notify );

static int RunManifestGenerator( ManifestState *pState );

static int HandlePrintRequest( ManifestState *pState, int32_t id );

static int HandleFileNotification( ManifestState *pState );

static FileRef *FindFileRef( ManifestState *pState, int id );

static int IncrementChangeCounter( ManifestState *pState );

static int AddLogEntry( ManifestState *pState, int id );

static int DumpChangeLog( ManifestState *pState, int fd );

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
                /* create varserver variables */
                SetupVars( &state );

                RunManifestGenerator( &state );
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
                " [-n] : max log entries\n"
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
    const char *options = "hvf:n:";

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

                case 'n':
                    pState->maxEntries = strtoul( optarg, NULL, 10 );
                    if ( pState->maxEntries > 0 )
                    {
                        pState->pChangeLog = calloc( pState->maxEntries,
                                                     sizeof( ChangeLogEntry ) );
                        if ( pState->pChangeLog == NULL )
                        {
                            printf("Cannot allocate change log\n");
                            pState->maxEntries = 0;
                        }
                    }
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
        /* create a notification file descriptor */
        pState->notifyfd = inotify_init1(IN_NONBLOCK);

        if ( pState->verbose == true )
        {
            printf("ProcessConfigFile: %s\n", pFileName );
        }

        /* parse the JSON config file */
        config = JSON_Process( pFileName );
        if ( config != NULL )
        {
            /* get the render variable name */
            pState->renderVarName = JSON_GetStr( config, "rendervar" );

            /* get the name of the counter variable */
            pState->countVarName = JSON_GetStr( config, "countvar" );

            /* get the name of the name of the change log variable */
            pState->changeLogName = JSON_GetStr( config, "changelog" );

            /* get the manifest name */
            pState->name = JSON_GetStr(config, "manifest");

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
                /* add an inotify watch on the file */
                pFileRef->id = inotify_add_watch( pState->notifyfd,
                                                  pFileRef->name,
                                                 IN_CLOSE_WRITE );

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

/*============================================================================*/
/*  SetupVars                                                                 */
/*!
    Set up the manifest variables

    The SetupVars function creates and configures the manifest variables

    @param[in]
        pState
            pointer to the Manifest State object

    @retval
        EOK - message variable successfully created
        EINVAL - invalid arguments

==============================================================================*/
static int SetupVars( ManifestState *pState )
{
    int result = EINVAL;
    int errcount = 0;
    int i;
    int n;
    VAR_HANDLE *pVarHandle;

    VarDef vars[] =
    {
        {  pState->renderVarName,
           VARFLAG_VOLATILE,
           NOTIFY_PRINT,
           &(pState->hRenderVar) },

        {  pState->changeLogName,
           VARFLAG_VOLATILE,
           NOTIFY_PRINT,
           &(pState->hChangeLog) },

        { pState->countVarName,
          VARFLAG_VOLATILE,
          NOTIFY_NONE,
          &(pState->hCountVar ) }
    };

    n = sizeof( vars ) / sizeof( vars[0] );

    if ( pState != NULL )
    {
        for ( i=0 ; i < n ; i++ )
        {
            if ( vars[i].name != NULL )
            {
                /* get a pointer to the location to store the variable handle */
                pVarHandle = vars[i].pVarHandle;
                if ( pVarHandle != NULL )
                {
                    /* create a message variable */
                    *pVarHandle = SetupVar( pState,
                                            vars[i].name,
                                            vars[i].flags,
                                            vars[i].notifyType );
                    if ( *pVarHandle == VAR_INVALID )
                    {
                        printf("Error creating variable: %s\n", vars[i].name );
                        errcount++;
                    }
                }
            }
        }
    }

    if ( errcount == 0 )
    {
        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  SetupVar                                                                  */
/*!
    Set up a variable

    The SetupVar function creates a varserver variable to be used to
    interact with the manifest generator.
    The variable may or may not have a notification associated with it.

@param[in]
    pState
        pointer to the Manifest State object

@param[in]
    name
        specify the variable name to create

@param[in]
    flags
        flags to add to the variable flag set

@param[in]
    notify
        specify the notification type.  Use NOTIFY_NONE if no notification is
        required

==============================================================================*/
VAR_HANDLE SetupVar( ManifestState *pState,
                     char *name,
                     uint32_t flags,
                     NotificationType notify )
{
    VAR_HANDLE hVar = VAR_INVALID;
    VarInfo info;
    int result;
    size_t len;

    if ( ( pState != NULL ) &&
         ( name != NULL ) )
    {
        len = strlen( name );
        if ( len < sizeof( info.name ) )
        {
            memset( &info, 0, sizeof( VarInfo ) );

            info.flags = flags;
            info.var.type = VARTYPE_UINT32;

            /* set the variable name */
            strcpy( info.name, name );

            /* create the variable */
            result = VARSERVER_CreateVar( pState->hVarServer, &info );
            if ( result == EOK )
            {
                hVar = info.hVar;
            }

            if ( hVar == VAR_INVALID )
            {
                hVar = VAR_FindByName( pState->hVarServer, info.name );
            }

            if ( ( hVar != VAR_INVALID ) &&
                    ( notify != NOTIFY_NONE ) )
            {
                /* set up variable notification */
                result = VAR_Notify( pState->hVarServer, hVar, notify );
                if ( result != EOK )
                {
                    printf( "VARMSG: Failed to set up notification for '%s'\n",
                            info.name );
                }
            }
        }
    }

    return hVar;
}

/*============================================================================*/
/*  RunManifestGenerator                                                      */
/*!
    Run the manifest generator service

    The RunManifestGenerator function waits for notifications from the
    variable server or from a file which has been modified

    @param[in]
        pState
            pointer to the Manifest State

    @retval EOK the manifest generator exited successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int RunManifestGenerator( ManifestState *pState )
{
    int result = EINVAL;
    int fd;
    int signum;
    int32_t sigval;
    VAR_HANDLE hVar;
    fd_set readfds;
    int n;

    if ( pState != NULL )
    {
        fd = VARSERVER_Signalfd();

        /* calculate the */
        n = fd;
        if ( pState->notifyfd > n )
        {
            n = pState->notifyfd;
        }
        n++;

        /* assume everything is ok until it is not */
        result = EOK;

        pState->running = true;
        while ( pState->running == true )
        {
            FD_ZERO( &readfds );
            FD_SET( fd, &readfds );
            FD_SET( pState->notifyfd, &readfds );

            /* wait for activity on the file descriptors */
            select( n, &readfds, NULL, NULL, 0 );
            if ( FD_ISSET( fd, &readfds ) )
            {
                /* get a variable server signal */
                signum = VARSERVER_WaitSignalfd( fd, &sigval );
                if ( signum == SIG_VAR_PRINT )
                {
                    /* handle a PRINT request */
                    result = HandlePrintRequest( pState, sigval );
                }
            }

            if ( FD_ISSET( pState->notifyfd, &readfds ) )
            {
                /* handle an inotify watch notification on a file */
                result = HandleFileNotification( pState );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HandlePrintRequest                                                        */
/*!
    Handle a varserver print request notification

    The HandlePrintRequest function handles a print request notification
    from the variable server.

    @param[in]
        pState
            pointer to the Manifest State

    @param[in]
        id
            print notification identifier

    @retval EOK print request notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandlePrintRequest( ManifestState *pState, int32_t id )
{
    int result = EINVAL;
    VAR_HANDLE hVar;
    int fd;

    if ( pState != NULL )
    {
        /* open a print session */
        if ( VAR_OpenPrintSession( pState->hVarServer,
                                   id,
                                   &hVar,
                                   &fd ) == EOK )
        {
            result = ENOENT;

            if ( hVar == pState->hRenderVar )
            {
                DumpManifest( pState, fd );
            }
            else if ( hVar == pState->hChangeLog )
            {
                DumpChangeLog( pState, fd );
            }

            /* Close the print session */
            result = VAR_ClosePrintSession( pState->hVarServer,
                                            id,
                                            fd );
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleFileNotification                                                    */
/*!
    Handle a file notification from an inotify watchlist

    The HandleFileNotification function reads file notification events
    from the inotify file descriptor and processes each notification
    received.

    Some systems cannot read integer variables if they are not
    properly aligned. On other systems, incorrect alignment may
    decrease performance. Hence, the buffer used for reading from
    the inotify file descriptor should have the same alignment as
    struct inotify_event.

    @param[in]
        pState
            pointer to the Manifest State

    @retval EOK file notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleFileNotification( ManifestState *pState )
{
    int result = EINVAL;
    char buf[4096]
        __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    bool done = false;
    char *ptr;
    FileRef *pFileRef;
    VarObject obj;
    char sha[65];

    /* Loop while events can be read from inotify file descriptor. */
    while( done == false )
    {
        /* Read some events. */
        len = read( pState->notifyfd, buf, sizeof(buf) );
        if ( len <= 0 )
        {
            done = true;
        }
        else
        {
            /* Loop over all events in the buffer. */
            ptr = buf;

            while ( ptr < ( buf + len ) )
            {
                /* get a pointer to an inotify_event to process */
                event = (const struct inotify_event *) ptr;
                if ( event->mask & IN_CLOSE_WRITE )
                {
                    /* find the appropriate file reference */
                    pFileRef = FindFileRef( pState, event->wd );
                    if ( pFileRef != NULL )
                    {
                        /* store the old SHA-256 */
                        strcpy( sha, pFileRef->sha );

                        /* update the manifest */
                        result = CalcManifest( pFileRef );
                        if ( result == EOK )
                        {
                            if ( strcmp( sha, pFileRef->sha ) != 0 )
                            {
                                /* Add log entry */
                                AddLogEntry( pState, pFileRef->id );

                                /* increment the change count */
                                result = IncrementChangeCounter( pState );
                            }
                        }
                    }
                }

                /* move to the next inotify event */
                ptr += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  IncrementChangeCounter                                                    */
/*!
    Increment the change counter by 1

    The IncrementChangeCounter function increments the change counter
    by 1 and updates the change counter variable if it is available.

    @param[in]
        pState
            pointer to the Manifest State

    @retval EOK the change counter was incremented
    @retval ENOENT no change counter was found
    @retval EINVAL invalid arguments

==============================================================================*/
static int IncrementChangeCounter( ManifestState *pState )
{
    int result = EINVAL;
    VarObject obj;

    if ( pState != NULL )
    {
        /* increment the change counter */
        pState->changeCount++;

        /* write the change counter to the counter variable */
        obj.type = VARTYPE_UINT32;
        obj.val.ul = pState->changeCount;

        if ( pState->hCountVar != VAR_INVALID )
        {
            result = VAR_Set( pState->hVarServer,
                              pState->hCountVar,
                              &obj );
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  FindFileRef                                                               */
/*!
    Search for a file reference in the manifest

    The FindFileRef function iterates through all the file references
    in the manifest looking for the one with the specified identifier.
    The identifier is assigned by inotify_add_watch at the time the
    file watch is created.

    @param[in]
        pState
            pointer to the Manifest State

    @param[id]
        id
            the inotify watch identifier to search for

    @retval pointer to the matching file reference
    @retval NULL if the file reference could not be found

==============================================================================*/
static FileRef *FindFileRef( ManifestState *pState, int id )
{
    FileRef *pFileRef = NULL;

    if ( pState != NULL )
    {
        pFileRef = pState->pManifest;
        while( pFileRef != NULL )
        {
            if ( pFileRef->id == id )
            {
                break;
            }

            pFileRef = pFileRef->pNext;
        }
    }

    return pFileRef;
}

/*============================================================================*/
/*  AddLogEntry                                                               */
/*!
    Add a circular buffer log entry

    The AddLogEntry function adds a change log record to the change log
    circular buffer.

    @param[in]
        pState
            pointer to the Manifest State containing the change log

    @param[id]
        fd
            output file descriptor

    @retval EOK entry added ok
    @retval ENOTSUP no circular buffer available
    @retval EINVAL invalid arguments

==============================================================================*/
static int AddLogEntry( ManifestState *pState, int id )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if ( pState->maxEntries > 0 )
        {
            /* store an entry in the circular buffer */
            pState->pChangeLog[pState->in].id = id;
            pState->pChangeLog[pState->in].t = time(NULL);

            /* indicate success */
            result = EOK;

            /* increment the input index and wrap it back to the
               beginning when it reaches the end of the circular buffer */
            (pState->in)++;
            if ( pState->in == pState->maxEntries )
            {
                /* wrap to beginning */
                pState->in = 0;
            }

            /* increment the number of entries in the circular buffer as
               long as we have not exceeded the buffer capacity */
            if ( pState->nEntries < pState->maxEntries )
            {
                /* increment the number of entries in the circular buffer */
                pState->nEntries++;
            }
            else
            {
                /* we have to move the output index forward since the
                   buffer is full and we just overwrote the oldest
                   buffer entry */
                (pState->out)++;
                if ( pState->out == pState->maxEntries )
                {
                    /* wrap output index */
                    pState->out = 0;
                }
            }
        }
        else
        {
            /* adding entries to the circular buffer is not supported */
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  DumpChangeLog                                                             */
/*!
    Dump the change log to the output file descriptor

    The DumpChangeLog function writes the change log content
    to the output file descriptor as a JSON object.

    @param[in]
        pState
            pointer to the Manifest State containing the change log

    @param[id]
        fd
            output file descriptor

    @retval EOK output generated ok
    @retval EINVAL invalid arguments

==============================================================================*/
static int DumpChangeLog( ManifestState *pState, int fd )
{
    int result = EINVAL;
    size_t idx;
    size_t n;
    size_t out;
    FileRef *pFileRef;
    ChangeLogEntry *entry;
    int count = 0;
    char timestr[128];

    /* write the opening brace */
    write( fd, "[", 1 );

    if ( pState != NULL )
    {
        result = EOK;

        n = pState->nEntries;
        out = pState->out;

        while ( n > 0 )
        {
            /* get a pointer to the circular buffer entry */
            entry = &pState->pChangeLog[out];

            /* look up the file reference */
            pFileRef = FindFileRef( pState, entry->id );
            if ( pFileRef != NULL )
            {
                /* prepend a comma if necessary */
                if ( count > 0 )
                {
                    write( fd, ",", 1 );
                }

                /* construct the time string */
                strftime( timestr,
                          sizeof( timestr ),
                          "%A %b %d %H:%M:%S %Y (GMT)",
                          gmtime( &(entry->t) ) );

                /* output the change log record */
                dprintf( fd,
                         "{ \"file\": \"%s\", \"time\" : \"%s\"}",
                         pFileRef->name,
                         timestr );

                /* increment the output counter */
                count++;
            }

            /* decrement the record counter */
            n--;

            /* advance the output reference */
            out++;

            /* wrap the output reference if necessary */
            if ( out == pState->maxEntries )
            {
                out = 0;
            }
        }
    }

    /* write the closing brace */
    write( fd, "]", 1 );

    return result;
}

/*! @}
 * end of manifest group */
