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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#include <search.h>
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

#ifndef MANIFEST_SHA_LEN
/*! length of the manifest SHA digest string */
#define MANIFEST_SHA_LEN  ( 65 )
#endif

/*! The FileRef object tracks a single file reference digest containing
    the file's name baseline and current digest, and reference to the
    inotify identifier */
typedef struct _fileRef
{
    /*! file name specifier */
    char *name;

    /*! calculated SHA256 */
    char sha[MANIFEST_SHA_LEN];

    /*! baseline SHA256 loaded from baseline file */
    char baseline[MANIFEST_SHA_LEN];

    /*! file watch id */
    int id;

    /*! flag to indicate if the FileRef object is part of a manifest list */
    bool inList;

    /*! flag to indicate if the FileRef object is part of the manifest hash */
    bool inHash;

    /*! pointer to the next FileRef object */
    struct _fileRef *pNext;
} FileRef;

/*! The DirRef object tracks all of the directories that we are watching */
typedef struct _dirRef
{
    /*! directory name */
    char *name;

    /*! directory watch id */
    int id;

    /*! pointer to next directory */
    struct _dirRef *pNext;
} DirRef;

/*! The ChangeLogEntry stores a single file change report */
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

    /*! name of the stats variable */
    char *statsVarName;

    /*! handle to the manifest stats variable */
    VAR_HANDLE hStats;

    /*! start time */
    time_t t0;

    /*! end time */
    time_t t1;

    /*! list of FileRef objects which make up the manifest */
    FileRef *pFileRef;

    /*! list of DirRef objects which are being tracked by the manifest */
    DirRef *pDirRef;

    /*! number of files being monitored */
    size_t nFiles;

    /*! count the number of times a monitored file has changed */
    size_t changeCount;

    /*! number of files in the baseline */
    size_t baselineCount;

    /*! count the number of files which differ from the baseline */
    size_t baselineDiffCount;

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

    /*! size of the manifest hash map */
    size_t mapsize;

    /*! hash table */
    struct hsearch_data *htab;

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

#ifndef MANIFEST_MAP_SIZE_DEFAULT
/*! default manifest map size */
#define MANIFEST_MAP_SIZE_DEFAULT  ( 500 )
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

static FileRef *UpdateFileRef( Manifest *pManifest,
                               char *pFileName,
                               char *pBaseline,
                               char *pSHA );
static FileRef *NewFileRef( char *pFileName, char *pBaseline, char *pSHA );
static int AddToManifest( Manifest *pManifest, FileRef *pFileRef );

static int AddSource( Manifest *pManifest, char *name );
static int AddDir( Manifest *pManifest, char *name );
static int AddFile( Manifest *pManifest, char *name );
static int AddDirWatch( Manifest *pManifest, char *name );

static int ProcessBaselineEntry( Manifest *pManifest, char *pName, char *pSHA );

static int AddBaselineSHA( FileRef *pFileRef, char *pSHA );

static int CalcManifest( FileRef *pFileRef );

static int MakeFileName( const char *dirname,
                         const char *filename,
                         char *out,
                         size_t len );

static int DumpManifest( Manifest *pManifest, int fd );

static int DumpStats( Manifest *pManifest, int fd );

static int SetupVars( VARSERVER_HANDLE hVarServer, Manifest *pManifest );

VAR_HANDLE SetupVar( VARSERVER_HANDLE hVarServer,
                     char *name,
                     uint32_t flags,
                     NotificationType notify );

static int RunManifestGenerator( ManifestState *pState );

static int HandleINotifyEvent( Manifest *pManifest,
                               const struct inotify_event *event,
                               VARSERVER_HANDLE hVarServer );

static int HandleCreateEvent( Manifest *pManifest,
                              const struct inotify_event *event,
                              VARSERVER_HANDLE hVarServer );

static int HandleDeleteEvent( Manifest *pManifest,
                              const struct inotify_event *event,
                              VARSERVER_HANDLE hVarServer );

static int HandleCloseWriteEvent( Manifest *pManifest,
                                  int id,
                                  VARSERVER_HANDLE hVarServer );

static int HandlePrintRequest( ManifestState *pState, int32_t id );

static int PrintManifestInfo( VAR_HANDLE hVar, Manifest *pManifest, int fd );

static int HandleFileNotification( VARSERVER_HANDLE hVarServer,
                                   Manifest *pManifest );

static FileRef *FindFileRef( Manifest *pManifest, int id );
static DirRef *FindDirRef( Manifest *pManifest, int id );

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

static void Output( int fd, char *buf, size_t len );

static int HashCreate( Manifest *pManifest );

static int HashAdd( Manifest *pManifest, FileRef *pFileRef );

static FileRef *HashFind( Manifest *pManifest, char *pFileName );

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
       if ( VARSERVER_Close( state.hVarServer ) == EOK )
       {
            state.hVarServer = NULL;
       }
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

    The ProcessConfigDir function processes all of the manifest configuration
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

            /* get the manifest t1 (initialization end) time */
            pManifest->t1 = time(NULL);

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
    diffvar (string) : name of the variable used to render manifest differences
    diffcountvar (string): name of the variable used to count differences
    statsvar (string) : name of the variable used to render manifest stats
    changelog (string) : name of the variable used to render the change log
    changeLogSize (integer) : number of entries to use for the change log
                              circular buffer
    baselinefile (string) : name of the (optional) output baseline file
    manifestfile (string) : name of the (optional) output manifest file
    dynamicfile (boolean) : if true, regenerate manifest file on change
    mapsize (int) : size of the manifest hash map
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
            /* set the default map size */
            pManifest->mapsize = MANIFEST_MAP_SIZE_DEFAULT;

            /* set the t0 time for the manifest */
            pManifest->t0 = time(NULL);

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

            /* get the name of the stats variable */
            pManifest->statsVarName = JSON_GetStr( pConfig, "statsvar");

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

            /* get the map size */
            JSON_GetNum( pConfig, "mapsize", &n );
            if ( n > 0 )
            {
                pManifest->mapsize = n;
            }

            if ( HashCreate( pManifest ) != EOK )
            {
                fprintf( stderr, "Failed to create manifest\n" );
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

    The AddSource function adds a source reference to the manifest.
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
static int MakeFileName( const char *dirname,
                         const char *filename,
                         char *out,
                         size_t len )
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
        rc = AddDirWatch( pManifest, name );
        if ( rc == -1 )
        {
            fprintf( stderr, "Failed to add watch: %s\n", name );
        }

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
/*  AddDirWatch                                                               */
/*!
    Add a watch to a directory

    The AddDirWatch function adds an inotify watch to the specified directory
    checking for additions and deletions to that directory.

    @param[in]
        pManifest
            pointer to the Manifest to add the files to

    @param[in]
        name
            name of the directory to add

    @retval EINVAL invalid arguments
    @retval EOK directory added ok

==============================================================================*/
static int AddDirWatch( Manifest *pManifest, char *name )
{
    int result = EINVAL;
    int rc;
    DirRef *pDirRef;

    if ( ( pManifest != NULL ) &&
         ( name != NULL ) )
    {
        /* allocate a DirRef object */
        pDirRef = calloc( 1, sizeof( DirRef ) );
        if ( pDirRef != NULL )
        {
            /* set the directory name */
            pDirRef->name = strdup( name );
            if ( pDirRef->name != NULL )
            {
                /* set up the watch */
                pDirRef->id = inotify_add_watch( pManifest->notifyfd,
                                                 name,
                                                 IN_CREATE | IN_DELETE );
                if ( pDirRef->id != -1 )
                {
                    if ( pManifest->pDirRef == NULL )
                    {
                        pManifest->pDirRef = pDirRef;
                    }
                    else
                    {
                        pDirRef->pNext = pManifest->pDirRef;
                        pManifest->pDirRef = pDirRef;
                    }

                    result = EOK;
                }
            }
        }

        if ( result != EOK )
        {
            if ( pDirRef != NULL )
            {
                if ( pDirRef->name != NULL )
                {
                    free( pDirRef->name );
                    pDirRef->name = NULL;
                }

                free( pDirRef );
                pDirRef = NULL;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  NewFileRef                                                                */
/*!
    Create a new FileRef object

    The NewFileRef function creates a new file reference object and
    optionally populates the baseline SHA and the current SHA.

    @param[in]
        pFileName
            pointer to the file name of the new File Reference object

    @param[in]
        pBaseline
            (optional) pointer to the baseline SHA

    @param[in]
        pSHA
            (optional) pointer to the current SHA

    @retval pointer to the new file reference
    @retval NULL if the file reference object could not be created

==============================================================================*/
static FileRef *NewFileRef( char *pFileName, char *pBaseline, char *pSHA )
{
    FileRef *pFileRef = NULL;
    size_t len;
    int errcount = 0;

    if ( pFileName != NULL )
    {
        pFileRef = calloc( 1, sizeof( FileRef ) );
        if ( pFileRef != NULL )
        {
            pFileRef->name = strdup( pFileName );
            if ( pFileRef->name != NULL )
            {
                if ( pBaseline != NULL )
                {
                    len = strlen( pBaseline );
                    if ( len < MANIFEST_SHA_LEN )
                    {
                        strcpy( pFileRef->baseline, pBaseline );
                    }
                    else
                    {
                        errcount++;
                    }
                }

                if ( pSHA != NULL )
                {
                    len = strlen( pSHA );
                    if ( len < MANIFEST_SHA_LEN )
                    {
                        strcpy( pFileRef->sha, pSHA );
                    }
                    else
                    {
                        errcount++;
                    }
                }
            }
            else
            {
                errcount++;
            }
        }

        if ( errcount > 0 )
        {
            if ( pFileRef != NULL )
            {
                if ( pFileRef->name != NULL )
                {
                    free( pFileRef->name );
                    pFileRef->name = NULL;
                }

                free( pFileRef );
                pFileRef = NULL;
            }
        }
    }

    return pFileRef;
}

/*============================================================================*/
/*  UpdateFileRef                                                             */
/*!
    Update a FileRef object

    The UpdateFileRef function searches for an existing file reference
    and updates the baseline SHA and, and the current SHA, if they are
    specified. If a FileRef is not found, it will create a new one using
    NewFileRef.

    @param[in]
        pManifest
            pointer to the manifest to get the existing FileRef from

    @param[in]
        pFileName
            pointer to the file name of the new File Reference object

    @param[in]
        pBaseline
            (optional) pointer to the baseline SHA

    @param[in]
        pSHA
            (optional) pointer to the current SHA

    @retval pointer to the new file reference
    @retval NULL if the file reference object could not be created

==============================================================================*/
static FileRef *UpdateFileRef( Manifest *pManifest,
                               char *pFileName,
                               char *pBaseline,
                               char *pSHA )
{
    FileRef *pFileRef = NULL;
    size_t len;

    if ( ( pManifest != NULL ) &&
         ( pFileName != NULL ) )
    {
        /* see if the file reference already exists */
        pFileRef = HashFind( pManifest, pFileName );
        if ( pFileRef != NULL )
        {
            if ( ( pManifest->notifyfd > 0 ) &&
                 ( pFileRef->id > 0 ) )
            {
                inotify_rm_watch( pManifest->notifyfd, pFileRef->id );
                pFileRef->id = 0;
            }

            if ( pBaseline != NULL )
            {
                len = strlen( pBaseline );
                if ( len < MANIFEST_SHA_LEN )
                {
                    strcpy( pFileRef->baseline, pBaseline );
                }
            }

            if ( pSHA != NULL )
            {
                len = strlen( pSHA );
                if ( len < MANIFEST_SHA_LEN )
                {
                    strcpy( pFileRef->sha, pSHA );
                }
            }
        }
        else
        {
            pFileRef = NewFileRef( pFileName, pBaseline, pSHA );
        }
    }

    return pFileRef;
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
    char *dupname;

    if ( ( pManifest != NULL ) &&
         ( name != NULL ) )
    {
        /* Create a new file reference */
        pFileRef = UpdateFileRef( pManifest, name, NULL, NULL );
        if ( pFileRef != NULL )
        {
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
                    /* add the file reference to the manifest */
                    result = AddToManifest( pManifest, pFileRef );
                    if ( result == EOK )
                    {
                        /* increment the manifest count */
                        pManifest->nFiles++;
                    }
                }
                else
                {
                    result = errno;

                    fprintf( stderr,
                             "Error watching %s: %s\n",
                             pFileRef->name,
                             strerror(result) );

                    if ( pFileRef->name != NULL )
                    {
                        free( pFileRef->name );
                    }

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
/*  AddToManifest                                                             */
/*!
    Add a file reference to the manifest

    The AddToManifest function adds the specified FileRef object to the
    manifest FileRef object list. If the FileRef has already been added
    then no action is taken.

    @param[in]
        pManifest
            pointer to the Manifest to add the file to

    @param[in]
        pFileRef
            pointer to the File Reference object to add

    @retval EINVAL invalid arguments
    @retval EOK file reference was successfully added to the manifest

==============================================================================*/
static int AddToManifest( Manifest *pManifest, FileRef *pFileRef )
{
    int result = EINVAL;

    if ( ( pManifest != NULL ) &&
         ( pFileRef != NULL ) )
    {
        result = EOK;

        if ( pFileRef->inList == false )
        {
            /* add the manifest entry file reference to the
                manifest list */
            pFileRef->pNext = pManifest->pFileRef;
            pManifest->pFileRef = pFileRef;

            /* set the flag to indicate that the file reference has
               been added to the manifest list */
            pFileRef->inList = true;
        }

        if ( pFileRef->inHash == false )
        {
            if ( pManifest->htab != NULL )
            {
                /* add the FileRef object to the manifest hash table */
                result = HashAdd( pManifest, pFileRef );
                if ( result == EOK )
                {
                    pFileRef->inHash = true;
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  AddBaselineSHA                                                            */
/*!
    Adds a baseline SHA to a FileReference object

    The AddBaselineSHA function adds the specified SHA to the specified
    FileRef baseline member.

    @param[in]
        pFileRef
            pointer to the FileRef object to add the baseline SHA to

    @param[in]
        pSHA
            pointer to the SHA digest to add

    @retval EINVAL invalid arguments
    @retval E2BIG the specified SHA is too big to add
    @retval EOK baseline SHA digest was successfully set

==============================================================================*/
static int AddBaselineSHA( FileRef *pFileRef, char *pSHA )
{
    int result = EINVAL;
    size_t len;

    if ( ( pFileRef != NULL ) &&
         ( pSHA != NULL ) )
    {
        len = strlen( pSHA );
        if ( len < MANIFEST_SHA_LEN )
        {
            strcpy( pFileRef->baseline, pSHA );
            result = EOK;
        }
        else
        {
            result = E2BIG;
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
        Output( fd, "{", 1 );

        if ( pManifest != NULL )
        {
            /* point to the first manifest entry */
            pFileRef = pManifest->pFileRef;
            while ( pFileRef != NULL )
            {
                if ( count > 0 )
                {
                    /* prepend a comma */
                    Output( fd, ",", 1 );
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
        Output( fd, "}", 1 );
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
        if ( VARSERVER_Close( state.hVarServer ) == EOK )
        {
            state.hVarServer = NULL;
        }
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
            &(pManifest->hBaselineDiff ) },

            { pManifest->statsVarName,
            VARFLAG_VOLATILE,
            NOTIFY_PRINT,
            &(pManifest->hStats ) }

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
        else if ( hVar == pManifest->hStats )
        {
            DumpStats( pManifest, fd );
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

    The HandleINotifyEvent function dispatches a received event to the
    appropriate event handler.

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        event
            pointer to the inotify_event to process

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK notification handled successfully
    @retval ENOENT not handled by this manifest
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleINotifyEvent( Manifest *pManifest,
                               const struct inotify_event *event,
                               VARSERVER_HANDLE hVarServer )
{
    int result = EINVAL;
    FileRef *pFileRef;

    if ( ( pManifest != NULL ) &&
         ( event != NULL ) &&
         ( hVarServer != NULL ) )
    {
        /* default error */
        result = ENOTSUP;

        /* check if the event is a write close event */
        if ( event->mask & IN_CLOSE_WRITE )
        {
            result = HandleCloseWriteEvent( pManifest, event->wd, hVarServer );

            /* return ENOENT to allow other manifests a chance to handle this */
            result = ENOENT;

        }
        else if ( event->mask & IN_CREATE )
        {
            result = HandleCreateEvent( pManifest, event, hVarServer );

            /* return ENOENT to allow other manifests a chance to handle this */
            result = ENOENT;
        }
        else if ( event->mask & IN_DELETE )
        {
            result = HandleDeleteEvent( pManifest, event, hVarServer );

            /* return ENOENT to allow other manifests a chance to handle this */
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleCloseWriteEvent                                                     */
/*!
    Handle an IN_CLOSE_WRITE event from inotify

    The HandleCloseWriteEvent function searches the FileRef list for the
    inotify identifier.  If the identifier is found a new SHA-256
    is calculated for the associated file. If the SHA-256 is different
    from its previous value, the HandleFileChange function is called
    to update the manifest state.

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        id
            an inotify identifier corresponding to a watched file

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK file notification handled successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int HandleCloseWriteEvent( Manifest *pManifest,
                                  int id,
                                  VARSERVER_HANDLE hVarServer )
{
    int result = EINVAL;
    FileRef *pFileRef;
    char sha[MANIFEST_SHA_LEN];

    if ( pManifest != NULL )
    {
        /* find the appropriate file reference */
        pFileRef = FindFileRef( pManifest, id );
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

    return result;
}

/*============================================================================*/
/*  FindDirRef                                                                */
/*!
    Search for a directory reference in the manifest

    The FindDirRef function iterates through all the directory references
    in the manifest looking for the one with the specified identifier.
    The identifier is assigned by inotify_add_watch at the time the
    directory watch is created.

    @param[in]
        pManifest
            pointer to the Manifest to search

    @param[in]
        id
            the inotify watch identifier to search for

    @retval pointer to the matching directory reference
    @retval NULL if the directory reference could not be found

==============================================================================*/
static DirRef *FindDirRef( Manifest *pManifest, int id )
{
    DirRef *pDirRef = NULL;

    if ( pManifest != NULL )
    {
        /* get a pointer to the first directory reference object */
        pDirRef = pManifest->pDirRef;
        while( pDirRef != NULL )
        {
            if( pDirRef->id == id )
            {
                /* found it! */
                break;
            }

            /* look in the next directory reference object */
            pDirRef = pDirRef->pNext;
        }
    }

    return pDirRef;
}

/*============================================================================*/
/*  HandleCreateEvent                                                         */
/*!
    Handle an inotify IN_CREATE event on a directory

    The HandleCreateEvent function constructs a fully qualified file name
    from the DirRef and the event file name, and adds this file as a watched
    file within the manifest.

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        event
            pointer to the received inotify_event structure

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK create event notification handled successfully
    @retval EINVAL invalid arguments
    @retval ENOTSUP no directory name
    @retval E2BIG file name cannot be constructed

==============================================================================*/
static int HandleCreateEvent( Manifest *pManifest,
                              const struct inotify_event *event,
                              VARSERVER_HANDLE hVarServer )
{
    char filename[PATH_MAX];
    int result = EINVAL;
    DirRef *pDirRef;
    FileRef *pFileRef;
    int rc;

    if ( ( pManifest != NULL ) &&
         ( event != NULL ) )
    {
        /* search for a matching directory reference in the manifest */
        pDirRef = FindDirRef( pManifest, event->wd );
        if ( pDirRef != NULL )
        {
            if ( pDirRef->name != NULL )
            {
                /* construct a fully qualified file name from the directory
                   reference name, and the filename from the event */
                result = MakeFileName( pDirRef->name,
                                       event->name,
                                       filename,
                                       sizeof( filename ) );
                if ( result == EOK )
                {
                    /* add a new file to be monitored within the manifest */
                    result = AddFile( pManifest, filename );
                    if ( result == EOK )
                    {
                        /* get the FileRef from the hash table */
                        pFileRef = HashFind( pManifest, filename );
                        if ( pFileRef != NULL )
                        {
                            /* handle file change manifest updates */
                            result = HandleFileChange( pManifest,
                                                    pFileRef,
                                                    hVarServer );
                        }
                    }
                }
            }
            else
            {
                result = ENOTSUP;
            }
        }
        else
        {
            result = ENOENT;
        }
    }

    return result;
}

/*============================================================================*/
/*  HandleDeleteEvent                                                         */
/*!
    Handle an inotify IN_DELETE event on a directory

    The HandleDeleteEvent function constructs a fully qualified file name
    from the DirRef and the event file name, searches for the FileRef
    within the manifest, and if found, updates the SHA as "DELETED"
    and then performs the file change handling to update the manifest
    status.

    @param[in]
        pManifest
            pointer to the manifest to update

    @param[in]
        event
            pointer to the received inotify_event structure

    @param[in]
        hVarServer
            handle to the variable server

    @retval EOK delete event notification handled successfully
    @retval EINVAL invalid arguments
    @retval ENOTSUP no directory name
    @retval E2BIG file name cannot be constructed

==============================================================================*/
static int HandleDeleteEvent( Manifest *pManifest,
                              const struct inotify_event *event,
                              VARSERVER_HANDLE hVarServer )
{
    char filename[PATH_MAX];
    int result = EINVAL;
    DirRef *pDirRef;
    FileRef *pFileRef;
    int rc;

    if ( ( pManifest != NULL ) &&
         ( event != NULL ) )
    {
        /* find the directory reference corresponding to the event */
        pDirRef = FindDirRef( pManifest, event->wd );
        if ( pDirRef != NULL )
        {
            if ( pDirRef->name != NULL )
            {
                /* construct a fully qualified file name */
                result = MakeFileName( pDirRef->name,
                                       event->name,
                                       filename,
                                       sizeof( filename ) );
                if ( result == EOK )
                {
                    /* get the file reference from the
                        manifest hash table */
                    pFileRef = HashFind( pManifest, filename );
                    if ( pFileRef != NULL )
                    {
                        /* mark the file as deleted */
                        strcpy(pFileRef->sha, "DELETED" );

                        /* decrement the file count */
                        pManifest->nFiles--;

                        /* remove the inotify watch */
                        if ( ( pManifest->notifyfd > 0 ) &&
                             ( pFileRef->id > 0 ) )
                        {
                            inotify_rm_watch( pManifest->notifyfd,
                                              pFileRef->id );
                            pFileRef->id = 0;
                        }

                        /* handle file change manifest updates */
                        result = HandleFileChange( pManifest,
                                                   pFileRef,
                                                   hVarServer );
                    }
                }
            }
            else
            {
                result = ENOTSUP;
            }
        }
        else
        {
            result = ENOENT;
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
        hVarServer
            handle to the variable server

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
/*  AppendChangeLogFile                                                       */
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
                           O_WRONLY | O_APPEND | O_CREAT,
                           0644 );
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
    Output( fd, "[", 1 );

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
                        Output( fd, ",", 1 );
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
    Output( fd, "]", 1 );

    return result;
}

/*============================================================================*/
/*  DumpStats                                                                 */
/*!
    Dump the manifest statistics to the output file descriptor

    The DumpStats function writes the manifest statistics
    to the output file descriptor as a JSON object.

    @param[in]
        pManifest
            pointer to the Manifest containing the statistics

    @param[in]
        fd
            output file descriptor

    @retval EOK output generated ok
    @retval EINVAL invalid arguments

==============================================================================*/
static int DumpStats( Manifest *pManifest, int fd )
{
    int result = EINVAL;
    char timestr[128];
    time_t duration;

    /* write the opening brace */
    Output( fd, "{", 1 );

    if ( pManifest != NULL )
    {
        result = EOK;

        dprintf( fd,
                 "\"baselinecount\":%lu,",
                 (unsigned long)pManifest->baselineCount );

        dprintf( fd, "\"filecount\":%lu,", (unsigned long)pManifest->nFiles );

        if ( pManifest->baseline != NULL )
        {
            dprintf( fd,
                     "\"baselinediff\":%lu,",
                     (unsigned long)pManifest->baselineDiffCount );
        }

        /* construct the time string */
        strftime( timestr,
                sizeof( timestr ),
                MANIFEST_TIME_FORMAT_STRING,
                gmtime( &pManifest->t0 ) );

        dprintf( fd, "\"init\":\"%s\",", timestr );

        duration = pManifest->t1 - pManifest->t0;
        dprintf (fd, "\"duration\" : %ld", duration );

    }

    /* write the closing brace */
    Output( fd, "}", 1 );

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
            fd = open( filename, O_WRONLY | O_CREAT, 0644 );
            if ( fd != -1 )
            {
                /* truncate the file */
                if ( ftruncate( fd, 0 ) == 0 )
                {
                    /* output the manifest */
                    result = DumpManifest( pManifest, fd );
                }
                else
                {
                    result = errno;
                }

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
    int rc;
    JNode *pBaseline;
    JNode *pNode = NULL;
    JVar *pValue;
    char *pName;
    char *pSHA;
    JObject *pObject;
    static int idx = 0;

    if ( pManifest != NULL )
    {
        result = EOK;

        /* initialize the baseline count */
        pManifest->baselineCount = 0;

        if ( pManifest->baseline != NULL )
        {
            /* load the baseline file */
            pBaseline = JSON_Process( pManifest->baseline );
            if ( ( pBaseline != NULL ) &&
                 ( pBaseline->type == JSON_OBJECT ) )
            {
                pObject = (JObject *)pBaseline;
                pNode = pObject->pFirst;
            }

            while ( pNode != NULL )
            {
                if ( pNode->type == JSON_VAR )
                {
                    pValue = (JVar *)pNode;
                    if ( pValue->var.type == JVARTYPE_STR )
                    {
                        pName = pValue->node.name;
                        pSHA = pValue->var.val.str;

                        /* process a baseline entry and
                           add it to the manifest */
                        rc = ProcessBaselineEntry( pManifest, pName, pSHA );
                        if ( rc == EOK )
                        {
                            /* increment the baseline file counter */
                            pManifest->baselineCount++;
                        }
                    }
                }

                /* move to the next baseline entry to be processed */
                pNode = pNode->pNext;
            }

            if ( pBaseline != NULL )
            {
                /* free the JSON baseline object */
                JSON_Free( pBaseline );
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
/*  ProcessBaselineEntry                                                      */
/*!
    Process a single baseline entry

    The ProcessBaselineEntry function proceses a single baseline entry
    consisting of the name of the file, and the baseline SHA loaded from
    the baseline file.

    The baseline entry is added to the manifest hash map if it is not
    there already, and added to the manifest file reference list if it
    is not there already.

    @param[in]
        pManifest
            pointer to the Manifest to load the baseline for

    @param[in]
        pName
            pointer to the name of a baseline entry

    @param[in]
        pSHA
            pointer to the baseline SHA for the specified file

    @retval EOK baseline loaded ok
    @retval ENOTSUP the baseline is not enabled
    @retval E2BIG one or more baseline SHAs are too long
    @retval ENOMEM memory allocation failure
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessBaselineEntry( Manifest *pManifest, char *pName, char *pSHA )
{
    int result = EINVAL;
    int rc;
    FileRef *pFileRef;

    if ( ( pManifest != NULL ) &&
         ( pName != NULL ) &&
         ( pSHA != NULL ) )
    {
        /* assume everything is ok, until it is not */
        result = EOK;

        /* get the file reference from the
            manifest hash table */
        pFileRef = HashFind( pManifest, pName );
        if ( pFileRef != NULL )
        {
            /* update File Reference with the baseline SHA */
            rc = AddBaselineSHA( pFileRef, pSHA );
            if ( rc != EOK )
            {
                fprintf( stderr,
                         "Failed to add baseline SHA to %s\n",
                         pName );

                result = rc;
            }
        }
        else
        {
            /* create a new File Reference object and set its name
               and baseline SHA value */
            pFileRef = NewFileRef( pName, pSHA, NULL );
        }

        if ( result == EOK )
        {
            /* add the file reference to the manifest if it
                is not present already */
            result = AddToManifest( pManifest, pFileRef );
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
    int rc;

    if ( pManifest != NULL )
    {
        result = EOK;

        if ( pManifest->baseline != NULL )
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
            pManifest->baselineDiffCount = count;

            if ( pManifest->hBaselineMismatchCount != VAR_INVALID )
            {
                obj.type = VARTYPE_UINT32;
                obj.val.ul = count;
                rc = VAR_Set( hVarServer,
                              pManifest->hBaselineMismatchCount,
                              &obj );
                if ( rc != EOK )
                {
                    result = rc;
                }
            }
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
            Output( fd, "[", 1);

            pFileRef = pManifest->pFileRef;
            while( pFileRef != NULL )
            {
                if ( strcmp( pFileRef->sha, pFileRef->baseline ) != 0 )
                {
                    if ( count++ != 0 )
                    {
                        /* prepend comma separator */
                        Output( fd, ",", 1 );
                    }

                    dprintf( fd, "\"%s\"", pFileRef->name );
                }

                /* move to the next file reference in the manifest */
                pFileRef = pFileRef->pNext;
            }

            /* output the JSON closing list brace */
            Output( fd, "]", 1 );

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

/*============================================================================*/
/*  Output                                                                    */
/*!
    Output a buffer to an output file descriptor

    The Output function wraps the write() system call and performs
    error checking.

    @param[in]
        fd
            output file descriptor

    @param[in]
        buf
            pointer to output buffer

    @param[in]
        len
            number of bytes to write

==============================================================================*/
static void Output( int fd, char *buf, size_t len )
{
    int n;

    if ( ( buf != NULL ) &&
         ( fd != -1 ) &&
         ( len > 0 ) )
    {
        n = write( fd, buf, len );
        if ( (size_t)n != len )
        {
            fprintf( stderr, "write failed\n" );
        }
    }
}

/*============================================================================*/
/*  HashCreate                                                                */
/*!
    Create a new hash table for the manifest

    The HashCreate function creates a new hash table for the specified
    manifest. The size of the hash table should be predefined in
    pManifest->mapsize

    @param[in]
        pManifest
            pointer to the manifest to create the hash table for

    @retval EOK has table created ok
    @retval ENOMEM memory allocation failure
    @retval EINVAL invalid arguments

==============================================================================*/
static int HashCreate( Manifest *pManifest )
{
    int result = EINVAL;
    int rc;

    if ( pManifest != NULL )
    {
        /* allocate memory for the manifest hsearch_data */
        pManifest->htab = calloc( 1, sizeof( struct hsearch_data ) );
        if ( pManifest->htab != NULL )
        {
            rc = hcreate_r( pManifest->mapsize, pManifest->htab );
            if ( rc == 0 )
            {
                result = errno;
                fprintf( stderr,
                         "HashCreate Error: %s : %s\n",
                         pManifest->name,
                         strerror( result ) );

            }
            else
            {
                result = EOK;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  HashAdd                                                                   */
/*!
    Add a new FileRef to the manifest hash table

    The HashAdd function adds a new FileRef to the manifest hash
    table.

    @param[in]
        pManifest
            pointer to the manifest to add to

    @param[in]
        pFileRef
            pointer to the FileRef object to add

    @retval EOK the FileRef object was successfully added to the manifest hash
    @retval ENOMEM memory allocation failure
    @retval EINVAL invalid arguments
    @retval ENOTSUP no hash table exists in the specified manifest

==============================================================================*/
static int HashAdd( Manifest *pManifest, FileRef *pFileRef )
{
    int result = EINVAL;
    ENTRY e;
    ENTRY *ep = NULL;

    if ( ( pManifest != NULL ) &&
         ( pFileRef != NULL ) &&
         ( pFileRef->name != NULL ) )
    {
        if ( pManifest->htab != NULL )
        {
            e.key = pFileRef->name;
            e.data = pFileRef;

            /* enter the value into the hash table */
            if ( ( hsearch_r( e, ENTER, &ep, pManifest->htab ) != 0 ) &&
                 ( ep != NULL ) )
            {
                result = EOK;
            }
            else
            {
                result = errno;
                fprintf( stderr,
                         "HashAdd Error: %s : %s\n",
                         pFileRef->name,
                         strerror( result ) );

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
/*  HashFind                                                                  */
/*!
    Search for a File Reference in the manifest hash table

    The HashFind function searches for a file reference in the specified
    manifest's hash table.

    @param[in]
        pManifest
            pointer to the manifest to search

    @param[in]
        pFileName
            pointer to name of a file to search for

    @retval pointer to the found FileRef object
    @retval NULL the FileRef was not found

==============================================================================*/
static FileRef *HashFind( Manifest *pManifest, char *pFileName )
{
    int result = EINVAL;
    ENTRY *ep = NULL;
    ENTRY e;
    FileRef *pFileRef = NULL;

    if ( ( pManifest != NULL ) &&
         ( pFileName != NULL ) )
    {
        if ( pManifest->htab != NULL )
        {
            e.key = pFileName;
            e.data = NULL;
            if ( hsearch_r( e, FIND, &ep, pManifest->htab ) != 0 )
            {
                result = EOK;
            }
        }

        if ( ( ep != NULL ) && ( result == EOK ) )
        {
            pFileRef = (FileRef *)(ep->data);
        }
    }

    return pFileRef;
}

/*! @}
 * end of manifest group */
