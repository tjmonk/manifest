# manifest
Manifest Generator

The manifest service monitors one or more manifests to determine if
any of the files referenced by the manifest have changed.

Each manifest definition is a JSON object contained in a configuration
file or file(s) which is specified on the command line of the manifest
service.

The manifest service supports the following command line arguments:

- -d : specify the name of a directory containing one or more manifest configs

- -f : specify the name of a file containing one or more manifest configs

- -h : display command help

- -v : enable verbose output

A manifest consists of a list files and directories to be monitored.
If a directory is specified, then all files in that directory will be added
to the list of monitored files.

Each monitored file will have a SHA-256 digest calculated for it. If the
file is changed at runtime, a new SHA-256 digest will be generated for it.
At any time you can output the manifest via a varserver variable or
via an output file.  The behavior of each manifest is controlled by the manifest
definition object.

Each manifest configuration file can consist of a single manifest definition
JSON object, or a list of manifest definition objects.  If specifying a
configuration directory, multiple manifest definition files can be processed
from the single directory.

The manifest definition object contains the following attributes:

- manifest : the name of the manifest
- rendervar : the name of a variable to dump the manifest as a JSON object
- countvar : the name of a variable that tracks the number of manifest changes
- changelog : the name of a variable to dump an in-memory changelog
- changelogsize : the size of the in-memory change log
- changelogfile : the name of a file to write manifest changes into
- sources : a list of files/directories to monitor
- manifestfile : name of a file to write the manifest into
- dynamicfile : boolean : true = re-create manifest file on every change
- diffcountvar: the name of a variable to count the number of changed files
- diffvar : the name of a variable to list the changed files
- baselinefile : the name of a file to write a baseline manifest

An example manifest definition is shown below:

```
    {
        "manifest" : "manifest1",
        "rendervar" : "/sys/manifest/info",
        "countvar" : "/sys/manifest/changecount",
        "diffvar" : "/sys/manifest/diff",
        "diffcountvar" : "/sys/manifest/diffcount",
        "changelog" : "/sys/manifest/changelog",
        "changelogsize" : 10,
        "changelogfile" : "/tmp/manifest_changelog.txt",
        "baselinefile" : "/tmp/manifest_baseline.txt",
        "manifestfile" : "/tmp/manifest.txt",
        "dynamicfile" : true,
        "sources" : [
            "/root/manifest/src/manifest.c"
        ]
    }
```

# Running the manifest service

The manifest service can be started as follows:

```
manifest -f <config.json> &
```
where <config.json> is the name of a manifest definition file.

Alternative, you could start the manifest service and have it look in a directory for one or more configurations as follows:

```
manifest -d /etc/manifests &
```

# Defining a Manifest Configuration

The manifest configuration is very flexible.  Only the manifest name and the sources list are mandatory configuration items.  Everything else is optional. The Manifest can be configured to output data via varserver variables, or by writing directly to files on disk.  Using varserver variables is more efficient than writing the manifest to disk since everything is held in memory and only rendered when it is requested.  Writing files to disk every time they change is relatively expensive in comparison. However, if you want to write files to disk, you can specify the filenames in the following configuration variables:

- changelogfile
- baselinefile
- manifestfile

If you set the dynamicfile variable to true, a new manifest file will
be generated every time one of the files monitored within the manfiest changes.

The baseline file is necessary to calculate some delta information,
such as the number of files which have changed from the baseline,
and the list of files which have changed from the baseline.

See "Using a baseline manifest" for more details.

# Using a baseline manifest
A baseline manifest is written to a file, but only if it does not already exist.  This allows, for example, to create a baseline snapshot of files for a particular firmware version.  Typically you would put this file somewhere it would not get overwritten, and include the firmware version as part of the file name.

Once a baseline manifest exists, you can do the following:

- count the number of files which differ from the baseline
- list the files whose SHA-256 digest differs from the baseline

# Basic Manifest Definition

The most basic manifest definition just consists of a manifest
name, a list of sources, and either a manifest file or a manifest rendervar.

A simple example is show below:

```
{
    "manifest" : "manifest3",
    "rendervar" : "/sys/manifest3/info",
    "sources" : [
        "/root/manifest/src/manifest.c"
    ]
}
```

You can get a dump of the manifest as follows:

$ getvar /sys/manifest3/info

{"/root/manifest/src/manifest.c":"b8ce900805133cd0cfa4cf8f20ca6ccb348ec1f51e0203428649e8ce4fac2ece"}

Of course, the variable name may vary depending on the names in the manifest definition file.

