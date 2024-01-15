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
#include <sys/signalfd.h>
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

    /*! baseline SHA256 loaded from baseline file */
    char baseline[65];

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

/*! Manifest Configuration object */
typedef struct _manifest
{
    /*! notify file descriptor */
    int notifyfd;

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

    /*! name of the baseline mismatch counter variable */
    char *diffCountVarName;

    /*! handle to the baseline mismatch counter variable */
    VAR_HANDLE hBaselineMismatchCount;

    /*! name of the baseline difference list */
    char *diffVarName;

    /*! handle to the baseline difference variable */
    VAR_HANDLE hBaselineDiff;

    /*! list of FileRef objects which make up the manifest */
    FileRef *pFileRef;

    /*! count the number of times a monitored file has changed */
    size_t changeCount;

    /*! maximum number of change log entries */
    size_t maxEntries;

    /*! number of entries in the circular buffer */
    size_t nEntries;

    /*! indicate start of the circular log */
    size_t in;

    /*! indicate end of the circular log */
    size_t out;

    /*! pointer to the change log */
    ChangeLogEntry *pChangeLog;

    /*! manifest baseline file (written once) */
    char *baseline;

    /*! manifest output file */
    char *manifestfile;

    /*! change log file name */
    char *changelogfile;

    /*! dynamic file output */
    bool dynamicfile;

    /*! pointer to the next manifest in the list */
    struct _manifest *pNext;

} Manifest;

/*! Manifest state object */
typedef struct _manifestState
{
    /*! variable server handle */
    VARSERVER_HANDLE hVarServer;

    /*! verbose flag */
    bool verbose;

    /*! name of the configuration directory */
    char *pConfigDir;

    /*! name of the configuration file */
    char *pConfigFile;

    /*! flag to keep the manifest generator service running */
    bool running;

    /*! pointer to the first manifest in the manifest list */
    Manifest *pManifest;

    /*! variable server file descriptor */
    int varserverfd;

    /*! number of manifests we are handling */
    size_t numManifests;

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

#ifndef MANIFEST_TIME_FORMAT_STRING
/*! time format string for the manifest change log timestamp */
#define MANIFEST_TIME_FORMAT_STRING "%A %b %d %H:%M:%S %Y (GMT)"
#endif

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

static int InitReadFds( ManifestState *pState, fd_set *fds );

static int ProcessSources( Manifest *pManifest, JArray *pSources );
static int ProcessConfigDir( ManifestState *pState, char *dirname );
static int ProcessConfigFile( ManifestState *pState, char *filename );
static int ProcessManifestArray( ManifestState *pState,
                                 JArray *pArray,
                                 char *filename );
static int ProcessManifestConfig( ManifestState *pState, JNode *config );
static Manifest *CreateManifest( JNode *pConfig );

static int AddSource( Manifest *pManifest, char *name );
static int AddDir( Manifest *pManifest, char *name );
static int AddFile( Manifest *pManifest, char *name );

static int CalcManifest( FileRef *pFileRef );

static int MakeFileName( char *dirname, char *filename, char *out, size_t len );

static int DumpManifest( Manifest *pManifest, int fd );

static int SetupVars( VARSERVER_HANDLE hVarServer, Manifest *pManifest );

VAR_HANDLE SetupVar( VARSERVER_HANDLE hVarServer,
                     char *name,
                     uint32_t flags,
                     NotificationType notify );

static int RunManifestGenerator( ManifestState *pState );

static int HandleINotifyEvent( Manifest *pManifest,
                               const struct inotify_event *event,
                               VARSERVER_HANDLE hVarServer );

static int HandlePrintRequest( ManifestState *pState, int32_t id );

static int PrintManifestInfo( VAR_HANDLE hVar, Manifest *pManifest, int fd );

static int HandleFileNotification( VARSERVER_HANDLE hVarServer,
                                   Manifest *pManifest );

static FileRef *FindFileRef( Manifest *pManifest, int id );

static int HandleFileChange( Manifest *pManifest,
                             FileRef *pFileRef,
                             VARSERVER_HANDLE hVarServer );

static int IncrementChangeCounter( VARSERVER_HANDLE hVarServer,
                                   Manifest *pManifest );

static int DumpChangeLog( Manifest *pManifest, int fd );

static int AddLogEntry( Manifest *pManifest, int id, time_t timestamp );

static int AppendChangeLogFile( Manifest *pManifest, int id, time_t timestamp );

static int WriteManifestFile( Manifest *pManifest,
                              char *filename,
                              bool checkExists );

static int LoadBaseline( Manifest *pManifest );

static int CompareBaseline( Manifest *pManifest, VARSERVER_HANDLE hVarServer );

static int WriteBaselineDiff( Manifest *pManifest, int fd );

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
            if ( result != EOK )
            {
                fprintf( stderr,
                         "Error processing config file: %s\n",
                         state.pConfigFile );
            }
        }

        if ( state.pConfigDir != NULL )
        {
            /* Process the configuration directory */
            result = ProcessConfigDir( &state, state.pConfigDir );
            if ( result != EOK )
            {
                fprintf( stderr,
                         "Error processing config dir: %s\n",
                         state.pConfigDir );
            }
        }

        if ( state.numManifests > 0 )
        {
            /* wait for and processs manifest events */
            (void)RunManifestGenerator( &state );
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
        fprintf( stderr,
                 "usage: %s [-v] [-h] [-f config file] [-d config dir]\n"
                 " [-h] : display this help\n"
                 " [-v] : verbose output\n"
                 " [-f] : specify the manifest configuration file\n"
                 " [-d] : specify the manifest configuration directory\n",
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
    const char *options = "hvf:d:";

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

                case 'd':
                    pState->pConfigDir = strdup(optarg);
                    break;

                default:
                    break;
            }
        }
    }

    return 0;
}

/*============================================================================*/
/*  ProcessConfigDir                                                          */
/*!
    Process all of the manifest configurations in the specified directory

    The ProcessConfigDir function processes all of the manfiest configuration
    files in the specified directory.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        dirname
            pointer to the name of the directory to process

    @retval EINVAL invalid arguments
    @retval ENOENT the directory could not be opened
    @retval EOK file processed ok
    @retval other error as returned by ProcessConfigData

==============================================================================*/
static int ProcessConfigDir( ManifestState *pState, char *dirname )
{
    int result = EINVAL;
    struct dirent *entry;
    DIR *pDir;
    struct stat sb;
    char filename[BUFSIZ];
    int rc;

    if ( ( pState != NULL ) &&
         ( dirname != NULL ) )
    {
        /* set the default error code */
        result = ENOENT;

        /* open the specified directory */
        pDir = opendir( dirname );
        if( pDir != NULL )
        {
            /* assume everything is ok until it isnt */
            result = EOK;

            /* iterate through the directory entries */
            while( entry = readdir( pDir ) )
            {
                /* construct the file name from the directory name
                   and the file name */
                rc = MakeFileName( dirname,
                                   entry->d_name,
                                   filename,
                                   sizeof( filename ) );
                if ( rc == EOK )
                {
                    /* stat the file name */
                    rc = stat( filename, &sb );
                    if ( ( rc == 0 ) &&
                         ( ( sb.st_mode & S_IFMT ) == S_IFREG ) )
                    {
                        /* process the configuration file */
                        rc = ProcessConfigFile( pState, filename );
                        if ( rc != EOK )
                        {
                            fprintf( stderr,
                                     "Error processing %s\n",
                                     filename );
                            result = rc;
                        }
                    }
                }
            }

            /* close the directory */
            closedir( pDir );
        }
    }

    return result;
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
    Manifest *pManifest;
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
            if ( config->type == JSON_ARRAY )
            {
                /* process the array of manifest definitions */
                result = ProcessManifestArray( pState,
                                               (JArray *)config,
                                               pFileName );
            }
            else if ( config->type == JSON_OBJECT )
            {
                /* process a single manifest definition */
                result = ProcessManifestConfig( pState, config );
            }

            if ( result != EOK )
            {
                fprintf( stderr,
                         "Failed to process manifest: %s\n",
                         pFileName );
            }

            if ( pState->verbose == true )
            {
                printf("Processed Config: %s\n", pFileName );
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessManifestArray                                                      */
/*!
    Process an array of manifest definitions

    The ProcessManifestArray function processes an array of manifest
    definitions.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        pArray
            pointer to the Manifest definition JSON Array

    @param[in]
        filename
            pointer to the name of the file to load

    @retval EINVAL invalid arguments
    @retval EOK file processed ok
    @retval other error as returned by ProcessConfigData

==============================================================================*/
static int ProcessManifestArray( ManifestState *pState,
                                 JArray *pArray,
                                 char *filename )
{
    int result = EINVAL;
    int n;
    int i;
    JNode *pConfig;
    int rc;

    if ( ( pState != NULL ) &&
         ( pArray != NULL ) &&
         ( filename != NULL ) )
    {
        /* set default error code */
        result = ENOENT;

        /* handle an array of manifest definitions */
        n = JSON_GetArraySize( (JArray *)pArray );
        if ( n > 0 )
        {
            /* assume everything is ok until it is not */
            result = EOK;

            /* iterate through the manifest definitions */
            for ( i = 0; i < n ; i++ )
            {
                /* get a single manifest definition */
                pConfig = JSON_Index( pArray, i );
                if ( pConfig != NULL )
                {
                    /* process a manifest definition */
                    rc = ProcessManifestConfig( pState, pConfig );
                    if ( rc != EOK )
                    {
                        /* capture the error code */
                        result = rc;

                        fprintf( stderr,
                                    "Failed to process manifest %d "
                                    "in configuration: %s\n",
                                    i,
                                    filename );
                    }
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessManifestConfig                                                     */
/*!
    Process a manifest definition

    The ProcessManifestConfig function processes a manifest configuration
    definition to create a new manifest object.

    @param[in]
        pState
            pointer to the Manifest Generator state

    @param[in]
        config
            pointer to a JSON object containing a manifest definition

    @retval EINVAL invalid arguments
    @retval EOK manifest definition processed ok

==============================================================================*/
static int ProcessManifestConfig( ManifestState *pState, JNode *config )
{
    int result = EINVAL;
    Manifest *pManifest;
    int rc;

    if ( ( pState != NULL ) &&
         ( config != NULL ) )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* parse and create the manifest */
        pManifest = CreateManifest( config );
        if ( pManifest != NULL )
        {
            /* write the baseline manifest file */
            if ( pManifest->baseline != NULL )
            {
                rc = WriteManifestFile( pManifest,
                                        pManifest->baseline,
                                        true );
                if ( rc == EEXIST )
                {
                    rc = EOK;
                }

                if ( rc != EOK )
                {
                    fprintf( stderr,
                             "Failed to write manifest baseline: %s\n",
                             pManifest->baseline );

                    result = rc;
                }
            }

            /* write the manifest file */
            if ( pManifest->manifestfile != NULL )
            {
                rc = WriteManifestFile( pManifest,
                                        pManifest->manifestfile,
                                        false );
                if ( rc != EOK )
                {
                    fprintf( stderr,
                             "Failed to write manifest file: %s\n",
                             pManifest->manifestfile );

                    result = rc;
                }
            }

            /* load the baseline manifest */
            rc = LoadBaseline( pManifest );
            if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
            {
                result = rc;
            }

            /* set up variables for the manifest */
            rc = SetupVars( pState->hVarServer, pManifest );
            if ( rc != EOK )
            {
                fprintf( stderr, "Failed to setup manifest variables\n");
                result = rc;
            }

            /* perform initial baseline comparison */
            rc = CompareBaseline( pManifest, pState->hVarServer );
            if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
            {
                result = rc;
            }

            if ( result == EOK )
            {
                /* increment the number of manifests we are handling */
                pState->numManifests++;

                /* insert the manifest at the head of the manifest list */
                if ( pState->pManifest == NULL )
                {
                    pState->pManifest = pManifest;
                }
                else
                {
                    pManifest->pNext = pState->pManifest;
                    pState->pManifest = pManifest;
                }
            }
        }
        else
        {
            fprintf( stderr, "Failed to create manifest\n" );
            result = EBADMSG;
        }
    }
    else
    {
        fprintf( stderr, "Failed to process manifest\n" );
    }

    return result;
}

/*============================================================================*/
/*  CreateManifest                                                            */
/*!
    Create a new manifest from a JSON configuration node

    The CreateManifest function creates a new manifest object from
    the information in the specified configuration node.

    Configuration parameters are:

    manifest (string) : name of the manifest
    rendervar (string) : name of the variable used to render the manifest
    countvar (string) : name of the variable used to count manifest changes
    changelog (string) : name of the variable used to render the change log
    changeLogSize (integer) : number of entries to use for the change log
                              circular buffer
    sources: (array) : array of (string) source names

    @param[in]
        pConfig
            pointer to the Manifest configuration object

    @retval pointer to a newly created Manifest object
    @retval NULL if the manifest object could not be created

==============================================================================*/
static Manifest *CreateManifest( JNode *pConfig )
{
    int result = EINVAL;
    Manifest *pManifest = NULL;
    int fd;
    JNode *pNode;
    JArray *pSources;
    char *name = "unknown";
    int n = 0;

    if ( pConfig != NULL )
    {
        /* allocate memory for the manifest */
        pManifest = calloc( 1, sizeof( Manifest ) );
        if ( pManifest != NULL )
        {
            /* get the manifest name */
            name = JSON_GetStr( pConfig, "manifest" );
            pManifest->name = name;

            /* create a notification file descriptor */
            pManifest->notifyfd = inotify_init1(IN_NONBLOCK);
            if ( pManifest->notifyfd == -1 )
            {
                fprintf( stderr,
                         "Failed to set up notifications for %s\n",
                         name );
            }

            /* get the render variable name */
            pManifest->renderVarName = JSON_GetStr( pConfig, "rendervar" );

            /* get the name of the counter variable */
            pManifest->countVarName = JSON_GetStr( pConfig, "countvar" );

            /* get the name of the baseline difference variable */
            pManifest->diffVarName = JSON_GetStr( pConfig, "diffvar" );

            /* get the name of the name of the change log variable */
            pManifest->changeLogName = JSON_GetStr( pConfig, "changelog" );

            /* get the name of the baseline mismatch count variable */
            pManifest->diffCountVarName = JSON_GetStr( pConfig, "diffcountvar");

            /* get the manifest baseline filename */
            pManifest->baseline = JSON_GetStr( pConfig, "baselinefile" );

            /* get the manifest output file */
            pManifest->manifestfile = JSON_GetStr( pConfig, "manifestfile" );

            /* get the manifest changelog file */
            pManifest->changelogfile = JSON_GetStr( pConfig, "changelogfile" );

            /* get the dynamic file flag to re-write manifest file on change */
            pManifest->dynamicfile = JSON_GetBool( pConfig, "dynamicfile" );

            /* get the change log size */
            JSON_GetNum( pConfig, "changelogsize", &n );
            if ( n > 0 )
            {
                /* allocate memory for the change log */
                pManifest->pChangeLog = calloc( n, sizeof( ChangeLogEntry ) );
                if ( pManifest->pChangeLog != NULL )
                {
                    pManifest->maxEntries = n;
                }
            }

            /* get the sources list */
            pNode = JSON_Find( pConfig, "sources" );
            if ( pNode->type == JSON_ARRAY )
            {
                /* process the sources list */
                pSources = (JArray *)pNode;
                result = ProcessSources( pManifest, pSources );
                if ( result != EOK )
                {
                    fprintf( stderr,
                             "Error processing manifest sources: %s\n",
                             strerror( result ) );
                }
            }
        }
    }

    return pManifest;
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
static int ProcessSources( Manifest *pManifest, JArray *pSources )
{
    int result = EINVAL;
    JNode *pNode;
    JVar *pVar;
    int n;
    int i;
    int rc;
    int count = 0;
    char *name;

    if ( ( pManifest != NULL ) &&
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
                        rc = AddSource( pManifest, pVar->var.val.str );
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
                        fprintf( stderr, "Invalid source specification\n");
                        result = ENOTSUP;
                    }
                }
                else
                {
                    fprintf( stderr, "Invalid source index\n");
                    result = ENOTSUP;
                }
            }
        }

        if ( count == 0 )
        {
            /* no sources listed */
            name = ( pManifest->name != NULL ) ? pManifest->name : "unknown";
            fprintf( stderr,
                     "No sources in manifest configuration: %s\n",
                     name );
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
        pManifest
            pointer to the Manifest to add the source to

    @param[in]
        name
            name of the source to add

    @retval EINVAL invalid arguments
    @retval EOK sources processed ok
    @retval ENOTSUP unsupported file type
    @retval other error from stat

==============================================================================*/
static int AddSource( Manifest *pManifest, char *name )
{
    struct stat sb;
    int result = EINVAL;
    int rc;

    if ( ( pManifest != NULL ) &&
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
                    result = AddDir( pManifest, name );
                    break;

                case S_IFREG:
                    result = AddFile( pManifest, name );
                    break;

                default:
                    fprintf( stderr, "Unsupported filetype: %s\n", name );
                    result = ENOTSUP;
                    break;
            }
        }
        else
        {
            result = errno;
            fprintf( stderr, "Failed to stat: %s\n", name );
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
        pManifest
            pointer to the Manifest to add the files to

    @param[in]
        name
            name of the directory to add

    @retval EINVAL invalid arguments
    @retval EOK directory added ok

==============================================================================*/
static int AddDir( Manifest *pManifest, char *name )
{
    int result = EINVAL;
    struct dirent *entry;
    DIR *pDir;
    struct stat sb;
    char buf[BUFSIZ];
    char *pFile;
    int rc;
    int errcount = 0;

    if ( ( pManifest != NULL ) &&
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
                            result = AddFile( pManifest, buf );
                            if ( result != EOK )
                            {
                                errcount++;
                            }
                        }
                        else
                        {
                            /* cannot allocate memory */
                            fprintf( stderr,
                                     "Cannot allocate memory for %s\n",
                                     buf );
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
        pManifest
            pointer to the Manifest to add the file to

    @param[in]
        name
            name of the file to add to the manifest

    @retval EINVAL invalid arguments
    @retval EOK file was successfully added to the manifest
    @retval ENOMEM memory allocation failure
    @retval EBADF cannot open file

==============================================================================*/
static int AddFile( Manifest *pManifest, char *name )
{
    FileRef *pFileRef;
    int result = EINVAL;

    if ( ( pManifest != NULL ) &&
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
                pFileRef->id = inotify_add_watch( pManifest->notifyfd,
                                                  pFileRef->name,
                                                  IN_CLOSE_WRITE );
                if ( pFileRef->id != -1 )
                {
                    /* add the manifest entry file reference to the
                       manifest list */
                    pFileRef->pNext = pManifest->pFileRef;
                    pManifest->pFileRef = pFileRef;
                }
                else
                {
                    result = errno;

                    fprintf( stderr,
                             "Error watching %s: %s\n",
                             pFileRef->name,
                             strerror(result) );

                    free( pFileRef );
                }
            }
            else
            {
                free( pFileRef );
                fprintf( stderr, "Error calculating digest for %s\n", name );
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
        pManifest
            pointer to the Manifest to output

    @param[in]
        fd
            output file descriptor

    @retval EINVAL invalid arguments
    @retval EOK manifest output ok
    @retval EBADF invalid file descriptor

==============================================================================*/
static int DumpManifest( Manifest *pManifest, int fd )
{
    int result = EBADF;
    FileRef *pFileRef;
    int count = 0;

    if ( fd != -1 )
    {
        /* initialize default result */
        result = EINVAL;

        /* output the start of the JSON object */
        write( fd, "{", 1 );

        if ( pManifest != NULL )
        {
            /* point to the first manifest entry */
            pFileRef = pManifest->pFileRef;
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

            result = EOK;
        }

        /* output the end of the JSON object */
        write( fd, "}", 1 );
    }

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

    fprintf( stderr, "Abnormal termination of the manifest generator \n" );

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
        hVarServer
            handle to the variable server

    @param[in]
        pManifest
            pointer to the manifest containing the variables to set up

    @retval
        EOK - manifest variables successfully set up
        EINVAL - invalid arguments

==============================================================================*/
static int SetupVars( VARSERVER_HANDLE hVarServer, Manifest *pManifest )
{
    int result = EINVAL;
    int errcount = 0;
    int i;
    int n;
    VAR_HANDLE *pVarHandle;

    if ( pManifest != NULL )
    {
        VarDef vars[] =
        {
            {  pManifest->renderVarName,
            VARFLAG_VOLATILE,
            NOTIFY_PRINT,
            &(pManifest->hRenderVar) },

            {  pManifest->changeLogName,
            VARFLAG_VOLATILE,
            NOTIFY_PRINT,
            &(pManifest->hChangeLog) },

            { pManifest->countVarName,
            VARFLAG_VOLATILE,
            NOTIFY_NONE,
            &(pManifest->hCountVar ) },

            { pManifest->diffCountVarName,
            VARFLAG_VOLATILE,
            NOTIFY_NONE,
            &(pManifest->hBaselineMismatchCount ) },

            { pManifest->diffVarName,
            VARFLAG_VOLATILE,
            NOTIFY_PRINT,
            &(pManifest->hBaselineDiff ) }
        };

        n = sizeof( vars ) / sizeof( vars[0] );

        for ( i=0 ; i < n ; i++ )
        {
            if ( vars[i].name != NULL )
            {
                /* get a pointer to the location to store the variable handle */
                pVarHandle = vars[i].pVarHandle;
                if ( pVarHandle != NULL )
                {
                    /* create a message variable */
                    *pVarHandle = SetupVar( hVarServer,
                                            vars[i].name,
                                            vars[i].flags,
                                            vars[i].notifyType );
                    if ( *pVarHandle == VAR_INVALID )
                    {
                        fprintf( stderr,
                                 "Error creating variable: %s\n",
                                 vars[i].name );
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
    hVarServer
        handle to the variable server

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
VAR_HANDLE SetupVar( VARSERVER_HANDLE hVarServer,
                     char *name,
                     uint32_t flags,
                     NotificationType notify )
{
    VAR_HANDLE hVar = VAR_INVALID;
    VarInfo info;
    int result;
    size_t len;

    if ( name != NULL )
    {
        len = strlen( name );
        if ( len < sizeof( info.name ) )
        {
            memset( &info, 0, sizeof( VarInfo ) );

            info.flags = flags;
            info.var.type = VARTYPE_UINT32;

            /* set the variable name */
            strcpy( info.name, name );

            /* try to create the variable.  This will fail if the variable
               was already pre-created */
            result = VARSERVER_CreateVar( hVarServer, &info );
            if ( result == EOK )
            {
                hVar = info.hVar;
            }

            if ( hVar == VAR_INVALID )
            {
                /* search for the variable which may have been pre-created */
                hVar = VAR_FindByName( hVarServer, info.name );
            }

            if ( ( hVar != VAR_INVALID ) &&
                    ( notify != NOTIFY_NONE ) )
            {
                /* set up variable notification */
                result = VAR_Notify( hVarServer, hVar, notify );
                if ( result != EOK )
                {
                    fprintf( stderr,
                             "VARMSG: Failed to set up notification for '%s'\n",
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
    Manifest *pManifest;
    int signum;
    int32_t sigval;
    VAR_HANDLE hVar;
    fd_set readfds;
    int rc;
    int n;

    if ( pState != NULL )
    {
        /* create a non blocking */
        pState->varserverfd = VARSERVER_Signalfd( SFD_NONBLOCK );

        /* assume everything is ok until it is not */
        result = EOK;

        pState->running = true;
        while ( pState->running == true )
        {
            /* initialize the read file descriptor set */
            n = InitReadFds( pState, &readfds ) + 1;

            /* wait for activity on the file descriptors */
            select( n, &readfds, NULL, NULL, 0 );

            if ( FD_ISSET( pState->varserverfd, &readfds ) )
            {
                /* get a variable server signal */
                do
                {
                    signum = VARSERVER_WaitSignalfd( pState->varserverfd,
                                                     &sigval );
                    if ( signum == SIG_VAR_PRINT )
                    {
                        /* handle a PRINT request */
                        rc = HandlePrintRequest( pState, sigval );
                        if ( rc != EOK )
                        {
                            result = rc;
                        }
                    }

                } while ( signum != -1 );
            }

            pManifest = pState->pManifest;
            while( pManifest != NULL )
            {
                if ( FD_ISSET( pManifest->notifyfd, &readfds ) )
                {
                    /* handle an inotify watch notification on a file */
                    rc = HandleFileNotification( pState->hVarServer,
                                                 pManifest );
                    if ( rc != EOK )
                    {
                        result = rc;
                    }
                }

                pManifest = pManifest->pNext;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  InitReadFds                                                               */
/*!
    Initialize the read file descriptor set

    The InitReadFds function initializes the specified fd_set with the
    file descriptors for the variable server and the manifest objects.

    @param[in]
        pState
            pointer to the Manifest State

    @param[in]
        fds
            file descriptor set to initialize

    @retval the largest file descriptor in the set
    @retval -1 if the file descriptor set could not be updated

==============================================================================*/
static int InitReadFds( ManifestState *pState, fd_set *fds )
{
    int maxfd = -1;
    Manifest *pManifest;

    if ( ( pState != NULL ) &&
         ( fds != NULL ) )
    {
        /* zero the file descriptor set */
        FD_ZERO( fds );

        /* add the varserver file descriptor */
        if ( pState->varserverfd != -1 )
        {
            FD_SET( pState->varserverfd, fds );
            maxfd = pState->varserverfd;
        }

        /* add the manifest file descriptors */
        pManifest = pState->pManifest;
        while ( pManifest != NULL )
        {
            if ( pManifest->notifyfd != -1 )
            {
                FD_SET( pManifest->notifyfd, fds );
                if ( pManifest->notifyfd > maxfd )
                {
                    maxfd = pManifest->notifyfd;
                }
            }

            pManifest = pManifest->pNext;
        }
    }

    return maxfd;
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
static int HandlePrintRequest( ManifestState *pState,
                               int32_t id )
{
    int result = EINVAL;
    VAR_HANDLE hVar;
    int fd;
    Manifest *pManifest;

    if ( pState != NULL )
    {
        /* open a print session */
        if ( VAR_OpenPrintSession( pState->hVarServer,
                                   id,
                                   &hVar,
                                   &fd ) == EOK )
        {
            result = ENOENT;

            pManifest = pState->pManifest;
            while( pManifest != NULL )
            {
                /* try to print manifest information. This may return ENOENT
                   if the */
                result = PrintManifestInfo( hVar, pManifest, fd);
                if ( result == EOK )
                {
                    /* as soon as one item has been printed we can stop */
                    break;
                }

                /* move to the next manifest in the list */
                pManifest = pManifest->pNext;
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
/*  PrintManifestInfo                                                         */
/*!
    Handle a varserver print request notification

    The HandlePrintRequest function prints out the manifest data corresponding
    to the specified variable handle to the specified output file descriptor

    @param[in]
        hVar
            the handle to the variable associated with the data to print

    @param[in]
        pManifest
            pointer to the Manifest

    @param[in]
        pManifest
            pointer to the manifest to check the print request against

    @param[in]
        fd
            output file descriptor

    @retval EOK print request notification handled successfully
    @retval ENOENT print request is not for the specified manifest
    @retval EINVAL invalid arguments

==============================================================================*/
static int PrintManifestInfo( VAR_HANDLE hVar, Manifest *pManifest, int fd )
{
    int result = EINVAL;

    if ( pManifest != NULL )
    {
        result = ENOENT;

        if ( hVar == pManifest->hRenderVar )
        {
            DumpManifest( pManifest, fd );
        }
        else if ( hVar == pManifest->hChangeLog )
        {
            DumpChangeLog( pManifest, fd );
        }
        else if ( hVar == pManifest->hBaselineDiff )
        {
            WriteBaselineDiff( pManifest, fd );
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
        hVarServer
            handle to the variable server

    @param[in]
        pManifest
            pointer to the manifest to update

    @retval EOK file notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleFileNotification( VARSERVER_HANDLE hVarServer,
                                   Manifest *pManifest )
{
    int result = EINVAL;
    char buf[4096]
        __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    bool done = false;
    char *ptr;
    int rc;

    if ( ( hVarServer != NULL ) &&
         ( pManifest != NULL ) )
    {
        /* Loop while events can be read from inotify file descriptor. */
        while( done == false )
        {
            /* Read some events. */
            len = read( pManifest->notifyfd, buf, sizeof(buf) );
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

                    /* handle the inotify event */
                    rc = HandleINotifyEvent( pManifest, event, hVarServer );
                    if ( ( rc != EOK ) && ( rc != ENOENT ) )
                    {
                        /* capture all errors except ENOENT which is allowed */
                        result = rc;
                    }

                    /* move to the next inotify event */
                    ptr += sizeof(struct inotify_event) + event->len;
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleINotifyEvent                                                        */
/*!
    Handle a single received inotify event

    The HandleINotifyEvent function searches the FileRef list for the
    inotify identifier.  If the identifier is found a new SHA-256
    is calculated for the associated file. If the SHA-256 is different
    from its previous value, the HandleFileChange function is called
    to update the manifest state.

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        event
            pointer to the inotify_event to process

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK file notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleINotifyEvent( Manifest *pManifest,
                               const struct inotify_event *event,
                               VARSERVER_HANDLE hVarServer )
{
    int result = EINVAL;
    FileRef *pFileRef;
    char sha[65];

    if ( ( pManifest != NULL ) &&
         ( event != NULL ) &&
         ( hVarServer != NULL ) )
    {
        /* assume result is ok until it is not */
        result = EOK;

        /* check if the event is a write close event */
        if ( event->mask & IN_CLOSE_WRITE )
        {
            /* find the appropriate file reference */
            pFileRef = FindFileRef( pManifest, event->wd );
            if ( pFileRef != NULL )
            {
                /* store the old SHA-256 */
                strcpy( sha, pFileRef->sha );

                /* update the manifest */
                result = CalcManifest( pFileRef );
                if ( result == EOK )
                {
                    /* check for a file change */
                    if ( strcmp( sha, pFileRef->sha ) != 0 )
                    {
                        /* handle the file change */
                        result = HandleFileChange( pManifest,
                                                   pFileRef,
                                                   hVarServer );
                    }
                }
            }
            else
            {
                /* the notification was not found for this manifest */
                result = ENOENT;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleFileChange                                                          */
/*!
    Handle a changed file monitored by the manifest

    The HandleFileChange function performs actions when a monitored
    file has changed.  The actions include:

    - adding a changelog entry to the runtime circular buffer
    - writing an entry to the changelog file
    - re-writing the manifest file
    - incrementing the change counter

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        pFileRef
            pointer to the FileRef object for the changed file

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK file notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleFileChange( Manifest *pManifest,
                             FileRef *pFileRef,
                             VARSERVER_HANDLE hVarServer )
{
    int result = EINVAL;
    time_t timestamp;
    int rc;

    if ( ( pManifest != NULL ) &&
         ( pFileRef != NULL ) &&
         ( hVarServer != NULL ) )
    {
        /* assume everything is ok until it is not */
        result = EOK;

        /* get the timestamp */
        timestamp = time( NULL );

        /* Add log entry */
        rc = AddLogEntry( pManifest,
                          pFileRef->id,
                          timestamp );
        if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
        {
            result = rc;
        }

        /* append the change to the log file */
        rc = AppendChangeLogFile( pManifest,
                                  pFileRef->id,
                                  timestamp );
        if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
        {
            result = rc;
        }

        if ( pManifest->dynamicfile == true )
        {
            /* write out a new manifest file */
            rc = WriteManifestFile( pManifest,
                                    pManifest->manifestfile,
                                    false );
            if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
            {
                result = rc;
            }
        }

        /* perform baseline comparison (if enabled) */
        rc = CompareBaseline( pManifest, hVarServer );
        if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
        {
            result = rc;
        }

        /* increment the change count */
        rc = IncrementChangeCounter(hVarServer, pManifest );
        if ( ( rc != EOK ) && ( rc != ENOTSUP ) )
        {
            result = rc;
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

    @param[in]
        pManifest
            pointer to the Manifest to update

    @retval EOK the change counter was incremented
    @retval ENOTSUP no change counter was found
    @retval EINVAL invalid arguments

==============================================================================*/
static int IncrementChangeCounter( VARSERVER_HANDLE hVarServer,
                                   Manifest *pManifest )
{
    int result = EINVAL;
    VarObject obj;

    if ( pManifest != NULL )
    {
        /* increment the change counter */
        pManifest->changeCount++;

        /* write the change counter to the counter variable */
        obj.type = VARTYPE_UINT32;
        obj.val.ul = pManifest->changeCount;

        if ( pManifest->hCountVar != VAR_INVALID )
        {
            result = VAR_Set( hVarServer,
                              pManifest->hCountVar,
                              &obj );
        }
        else
        {
            result = ENOTSUP;
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
        pManifest
            pointer to the Manifest to search

    @param[in]
        id
            the inotify watch identifier to search for

    @retval pointer to the matching file reference
    @retval NULL if the file reference could not be found

==============================================================================*/
static FileRef *FindFileRef( Manifest *pManifest, int id )
{
    FileRef *pFileRef = NULL;

    if ( pManifest != NULL )
    {
        pFileRef = pManifest->pFileRef;
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
    circular buffer of a manifest.

    @param[in]
        pManifest
            pointer to the Manifest containing the change log

    @param[in]
        id
            the inotify watch identifier

    @param[in]
        timestamp
            the entry timestamp

    @retval EOK entry added ok
    @retval ENOTSUP no circular buffer available
    @retval EINVAL invalid arguments

==============================================================================*/
static int AddLogEntry( Manifest *pManifest, int id, time_t timestamp )
{
    int result = EINVAL;
    time_t now;
    int fd;
    FileRef *pFileRef;

    if ( pManifest != NULL )
    {
        if ( ( pManifest->pChangeLog != NULL ) &&
             ( pManifest->maxEntries > 0 ) )
        {
            /* store an entry in the circular buffer */
            pManifest->pChangeLog[pManifest->in].id = id;
            pManifest->pChangeLog[pManifest->in].t = timestamp;

            /* indicate success */
            result = EOK;

            /* increment the input index and wrap it back to the
               beginning when it reaches the end of the circular buffer */
            (pManifest->in)++;
            if ( pManifest->in == pManifest->maxEntries )
            {
                /* wrap to beginning */
                pManifest->in = 0;
            }

            /* increment the number of entries in the circular buffer as
               long as we have not exceeded the buffer capacity */
            if ( pManifest->nEntries < pManifest->maxEntries )
            {
                /* increment the number of entries in the circular buffer */
                pManifest->nEntries++;
            }
            else
            {
                /* we have to move the output index forward since the
                   buffer is full and we just overwrote the oldest
                   buffer entry */
                (pManifest->out)++;
                if ( pManifest->out == pManifest->maxEntries )
                {
                    /* wrap output index */
                    pManifest->out = 0;
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
/*  AppendChangeLogFile                                                               */
/*!
    Append an entry to the change log file

    The AppendChangeLogFile function adds a CSV change log record to the
    change log file.

    @param[in]
        pManifest
            pointer to the Manifest containing the change log file name

    @param[in]
        id
            the inotify watch identifier

    @param[in]
        timestamp
            the entry timestamp

    @retval EOK entry added ok
    @retval ENOTSUP the change log file is not enabled
    @retval ENOENT file reference not found
    @retval EINVAL invalid arguments
    @retval other error from open()

==============================================================================*/
static int AppendChangeLogFile( Manifest *pManifest, int id, time_t timestamp )
{
    time_t now;
    int fd;
    FileRef *pFileRef;
    char timestr[128];
    int result = EINVAL;

    if ( pManifest != NULL )
    {
        if ( pManifest->changelogfile != NULL )
        {
            /* look up the file reference */
            pFileRef = FindFileRef( pManifest, id );
            if ( ( pFileRef != NULL ) &&
                 ( pFileRef->name != NULL ) )
            {
                /* construct the time string */
                strftime( timestr,
                        sizeof( timestr ),
                        MANIFEST_TIME_FORMAT_STRING,
                        gmtime( &timestamp ) );

                /* open the file in append mode and create it if it
                    does not exist */
                fd = open( pManifest->changelogfile,
                        O_WRONLY | O_APPEND | O_CREAT );
                if ( fd != -1 )
                {
                    dprintf( fd,
                             "%s, %s\n",
                             timestr,
                             pFileRef->name );

                    result = EOK;
                }
                else
                {
                    result = errno;
                }

                close( fd );
            }
            else
            {
                result = ENOENT;
            }
        }
        else
        {
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
        pManifest
            pointer to the Manifest containing the change log

    @param[in]
        fd
            output file descriptor

    @retval EOK output generated ok
    @retval EINVAL invalid arguments

==============================================================================*/
static int DumpChangeLog( Manifest *pManifest, int fd )
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

    if ( pManifest != NULL )
    {
        result = EOK;

        if ( pManifest->pChangeLog != NULL )
        {
            n = pManifest->nEntries;
            out = pManifest->out;

            while ( n > 0 )
            {
                /* get a pointer to the circular buffer entry */
                entry = &pManifest->pChangeLog[out];

                /* look up the file reference */
                pFileRef = FindFileRef( pManifest, entry->id );
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
                            MANIFEST_TIME_FORMAT_STRING,
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
                if ( out == pManifest->maxEntries )
                {
                    out = 0;
                }
            }
        }
    }

    /* write the closing brace */
    write( fd, "]", 1 );

    return result;
}

/*============================================================================*/
/*  WriteManifestFile                                                         */
/*!
    Write the manifest to an output file

    The WriteManifestFile function writes the manifest out to the specified
    file. If the checkExists flag is set and the file already exists,
    then the file will not be output.

    @param[in]
        pManifest
            pointer to the Manifest to output

    @param[in]
        filename
            pointer to the output filename

    @param[in]
        checkExists
            true : check if the file exists and suppress output if it does
            false : always write the file

    @retval EOK manifest output ok
    @retval EEXIST the output file already exists
    @retval EBADF invalid file descriptor
    @retval EINVAL invalid arguments
    @retval other error from open()

==============================================================================*/
static int WriteManifestFile( Manifest *pManifest,
                              char *filename,
                              bool checkExists )
{
    int result = EINVAL;
    struct stat sb;
    int fd;

    if ( ( pManifest != NULL ) &&
         ( filename != NULL ) )
    {
        if ( checkExists == true )
        {
            /* check if the file exists */
            result = stat( filename, &sb );
            if ( result == EOK )
            {
                result = EEXIST;
            }
        }

        if ( result != EEXIST )
        {
            /* open the file in write only mode and create it if it
                does not exist */
            fd = open( filename, O_WRONLY | O_CREAT );
            if ( fd != -1 )
            {
                /* truncate the file */
                ftruncate( fd, 0 );

                /* output the manifest */
                result = DumpManifest( pManifest, fd );

                close( fd );
            }
            else
            {
                result = errno;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  LoadBaseline                                                              */
/*!
    Load the baseline manifest

    The LoadBaseline function loads the baseline manifest SHAs into the
    current manifest to be used to determine which files have changed
    from the baseline.

    @param[in]
        pManifest
            pointer to the Manifest to load the baseline for

    @retval EOK baseline loaded ok
    @retval ENOTSUP the baseline is not enabled
    @retval E2BIG one or more baseline SHAs are too long
    @retval ENOENT one or more files were not found in the baseline
    @retval EINVAL invalid arguments

==============================================================================*/
static int LoadBaseline( Manifest *pManifest )
{
    int result = EINVAL;
    JNode *pBaseline;
    FileRef *pFileRef;
    char *pSha;
    size_t len;

    if ( pManifest != NULL )
    {
        if ( pManifest->baseline != NULL )
        {
            /* load the baseline file */
            pBaseline = JSON_Process( pManifest->baseline );
            if ( pBaseline != NULL )
            {
                result = EOK;

                pFileRef = pManifest->pFileRef;
                while ( pFileRef != NULL )
                {
                    /* get the file baseline SHA */
                    pSha = JSON_GetStr( pBaseline, pFileRef->name );
                    if ( pSha != NULL )
                    {
                        /* get the length of the baseline SHA */
                        len = strlen( pSha );
                        if ( len < sizeof( pFileRef->baseline ) )
                        {
                            /* update the baseline SHA in the FileRef */
                            strcpy( pFileRef->baseline, pSha );
                        }
                        else
                        {
                            /* not enough room for the baseline SHA */
                            result = E2BIG;
                        }
                    }
                    else
                    {
                        /* baseline SHA not found */
                        memset( pFileRef->baseline,
                                0,
                                sizeof( pFileRef->baseline ) );

                        result = ENOENT;
                    }

                    /* move to the next file reference */
                    pFileRef = pFileRef->pNext;
                }
            }

            JSON_Free( pBaseline );
        }
        else
        {
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  CompareBaseline                                                           */
/*!
    Compare the current manifest against the baseline

    The CompareBaseline function compares the current manifest against
    the baseline manifest and counts the number of SHA entries which
    do not match. i.e the number of changed files.

    It updates the baseline mismatch counter variable.

    This function requires that the baseline has been established,
    and the baseline mismatch counter variable exists, both of
    which are optional configurations.

    @param[in]
        pManifest
            pointer to the Manifest to compare the baseline for

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK baseline comparison completed ok
    @retval ENOTSUP the baseline comparison is not enabled
    @retval EINVAL invalid arguments

==============================================================================*/
static int CompareBaseline( Manifest *pManifest, VARSERVER_HANDLE hVarServer )
{
    int result = EINVAL;
    uint32_t count = 0;
    FileRef *pFileRef;
    size_t len;
    VarObject obj;

    if ( pManifest != NULL )
    {
        if ( ( pManifest->baseline != NULL ) &&
             ( pManifest->hBaselineMismatchCount != VAR_INVALID ) )
        {
            /* get a pointer to the first file in the manifest */
            pFileRef = pManifest->pFileRef;
            while( pFileRef != NULL )
            {
                /* check the current SHA against the baseline SHA */
                if ( strcmp( pFileRef->sha, pFileRef->baseline ) != 0 )
                {
                    /* increment the mismatch counter */
                    count++;
                }

                /* check the next file reference */
                pFileRef = pFileRef->pNext;
            }

            /* update the baseline compare variable */
            obj.type = VARTYPE_UINT32;
            obj.val.ul = count;
            result = VAR_Set( hVarServer,
                            pManifest->hBaselineMismatchCount,
                            &obj );
        }
        else
        {
            /* baseline comparison is not enabled */
            result = ENOTSUP;
        }
    }

    return result;
}

/*============================================================================*/
/*  WriteBaselineDiff                                                         */
/*!
    Write the baseline difference list

    The WriteBaselineDiff function writes a JSON list of file names
    which do not match the reference baseline.  Note that if the
    baseline is not enabled, this will be the full list of files
    in the manifest set.

    @param[in]
        pManifest
            pointer to the Manifest to write the baseline difference for

    @param[in]
        fd
            output file descriptor

    @retval EOK baseline difference was written ok
    @retval EBADF invalid output file descriptor
    @retval EINVAL invalid arguments

==============================================================================*/
static int WriteBaselineDiff( Manifest *pManifest, int fd )
{
    int result = EINVAL;
    FileRef *pFileRef;
    int count = 0;

    if ( pManifest != NULL )
    {
        if ( fd != -1 )
        {
            /* output the JSON opening list brace */
            write( fd, "[", 1);

            pFileRef = pManifest->pFileRef;
            while( pFileRef != NULL )
            {
                if ( strcmp( pFileRef->sha, pFileRef->baseline ) != 0 )
                {
                    if ( count++ != 0 )
                    {
                        /* prepend comma separator */
                        write( fd, ",", 1 );
                    }

                    dprintf( fd, "\"%s\"", pFileRef->name );
                }

                /* move to the next file reference in the manifest */
                pFileRef = pFileRef->pNext;
            }

            /* output the JSON closing list brace */
            write( fd, "]", 1 );

            /* indicate success */
            result = EOK;
        }
        else
        {
            result = EBADF;
        }
    }

    return result;
}

/*! @}
 * end of manifest group */
